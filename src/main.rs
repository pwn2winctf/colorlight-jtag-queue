use bytes::BufMut;
use futures::TryStreamExt;
use std::convert::Infallible;
use uuid::Uuid;
use warp::{
    http::StatusCode,
    multipart::{FormData, Part},
    reject::Reject,
    Filter, Rejection, Reply,
};

mod hashcash;
mod pow;

const MAX_FILE_SIZE: u64 = 600_000;

#[tokio::main]
async fn main() {
    let pow_handler = pow::PoWHandler::new();
    let pow_handler_filter = warp::any().map(move || pow_handler.clone());
    let hashcash_filter = warp::header::<String>("x-hashcash")
        .or(warp::any().map(|| String::new()))
        .unify();

    let token_route = warp::path("token")
        .and(warp::get())
        .and(pow_handler_filter.clone())
        .and_then(get_token);

    let upload_route = warp::path("upload")
        .and(warp::post())
        .and(pow_handler_filter.clone())
        .and(hashcash_filter)
        .and(warp::multipart::form().max_length(MAX_FILE_SIZE))
        .and_then(upload);

    let router = upload_route.or(token_route).recover(handle_rejection);
    println!("Server started at localhost:8080");
    warp::serve(router).run(([0, 0, 0, 0], 8080)).await;
}

async fn get_token(pow_handler: pow::PoWHandler) -> Result<impl Reply, Rejection> {
    let token = pow_handler.get_token().unwrap();
    Ok(warp::reply::json(&token))
}

async fn upload(
    pow_handler: pow::PoWHandler,
    token: String,
    form: FormData,
) -> Result<impl Reply, Rejection> {
    pow_handler
        .validate_token(&token)
        .map_err(|e| warp::reject::custom(e))?;

    let parts: Vec<Part> = form.try_collect().await.map_err(|e| {
        eprintln!("form error: {}", e);
        warp::reject::reject()
    })?;

    for p in parts {
        if p.name() == "file" {
            let value = p
                .stream()
                .try_fold(Vec::new(), |mut vec, data| {
                    vec.put(data);
                    async move { Ok(vec) }
                })
                .await
                .map_err(|e| {
                    eprintln!("reading file error: {}", e);
                    warp::reject::reject()
                })?;

            let file_name = format!("./files/{}", Uuid::new_v4().to_string());
            tokio::fs::write(&file_name, value).await.map_err(|e| {
                eprint!("error writing file: {}", e);
                warp::reject::reject()
            })?;
            println!("created file: {}", file_name);
        }
    }

    Ok("success")
}

impl Reject for pow::PoWError {}

async fn handle_rejection(err: Rejection) -> std::result::Result<impl Reply, Infallible> {
    let (code, message) = if err.is_not_found() {
        (StatusCode::NOT_FOUND, "Not Found".to_string())
    } else if let Some(_) = err.find::<warp::reject::PayloadTooLarge>() {
        (StatusCode::BAD_REQUEST, "Payload too large".to_string())
    } else if let Some(e) = err.find::<pow::PoWError>() {
        (StatusCode::BAD_REQUEST, format!("{:#?}", e))
    } else {
        eprintln!("unhandled error: {:?}", err);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal Server Error".to_string(),
        )
    };

    Ok(warp::reply::with_status(message, code))
}
