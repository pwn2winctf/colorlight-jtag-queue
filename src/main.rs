mod hashcash;
mod pow;

use crate::pow::{PoWError, PoWManager};
use bytes::BufMut;
use dotenv::dotenv;
use futures::TryStreamExt;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::env::var;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::thread;
use thiserror::Error;
use uuid::Uuid;
use warp::{
    http::{
        header::{HeaderMap, HeaderValue},
        StatusCode,
    },
    multipart::{FormData, Part},
    reject::Reject,
    Filter, Rejection, Reply,
};
#[macro_use]
extern crate log;

lazy_static! {
    static ref MAX_FILE_SIZE: u64 = var("MAX_FILE_SIZE").unwrap().parse().unwrap();
    static ref MAX_PENDING_OPS: usize = var("MAX_PENDING_OPS").unwrap().parse().unwrap();
    static ref PROGRAMMING_TIMEOUT_SECS: u32 =
        var("PROGRAMMING_TIMEOUT_SECS").unwrap().parse().unwrap();
    static ref FPGA_RUN_TIME_SECS: u64 = var("FPGA_RUN_TIME_SECS").unwrap().parse().unwrap();
}

#[derive(Error, Debug)]
pub enum APIError {
    #[error("operational error: {0}")]
    OperationalError(String),
    #[error("error reading request: {0}")]
    ReadReqError(String),
    #[error("error writing file: {0}")]
    WriteFileError(String),
    #[error("error inserting request into queue: {0}")]
    EnqueueError(String),
    #[error("rw lock error: {0}")]
    RwLockError(String),
    #[error("request missing the 'file' field")]
    ReqMissingFile,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
enum FPGAState {
    Wait,
    Programming,
    Running,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct QueueStatus {
    enqueued: usize,
    consumed: usize,
    fpga: FPGAState,
}

#[derive(Debug, Clone)]
struct Queue {
    enqueued: Arc<AtomicUsize>,
    worker_state: Arc<AtomicUsize>,
    tx: mpsc::SyncSender<String>,
}

impl Queue {
    fn new() -> (Self, mpsc::Receiver<String>) {
        let (tx, rx) = mpsc::sync_channel(*MAX_PENDING_OPS);
        (
            Queue {
                enqueued: Arc::new(AtomicUsize::new(0)),
                worker_state: Arc::new(AtomicUsize::new(0)),
                tx,
            },
            rx,
        )
    }
}

fn worker_main(queue: Queue, rx: mpsc::Receiver<String>) {
    loop {
        let filename = match rx.recv() {
            Err(e) => {
                // since we did not retrieve anything from queue, we should not advance state
                error!("cannot receive filename from channel: {:?}", e);
                continue;
            }
            Ok(v) => v,
        };

        // state Wait -> Programming
        queue.worker_state.fetch_add(1, Ordering::SeqCst);

        info!(
            "programming {} ({}/{})",
            &filename,
            queue.worker_state.load(Ordering::SeqCst) / 3 + 1,
            queue.enqueued.load(Ordering::SeqCst)
        );

        let mut success = false;

        match Command::new("timeout")
            .arg(PROGRAMMING_TIMEOUT_SECS.to_string())
            .arg("./program")
            .arg(&filename)
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
        {
            Err(e) => {
                error!("error spawning child: {:?}", e);
            }
            Ok(mut child) => match child.wait() {
                Err(e) => error!("error waiting for child {}: {:?}", child.id(), e),
                Ok(status) => {
                    if status.success() {
                        success = true;
                    } else {
                        error!("programming failed with status {:?}", status);
                    }
                }
            },
        }

        let _ = std::fs::remove_file(&filename)
            .map_err(|e| error!("cannot remove file {:?}: {:?}", filename, e));

        if success {
            // state Programming -> Running
            queue.worker_state.fetch_add(1, Ordering::SeqCst);
            // wait and let run
            std::thread::sleep(std::time::Duration::from_secs(*FPGA_RUN_TIME_SECS));
            // state Running -> Wait
            queue.worker_state.fetch_add(1, Ordering::SeqCst);
        } else {
            // state Programming -> Wait
            queue.worker_state.fetch_add(2, Ordering::SeqCst);
        }
    }
}

#[tokio::main]
async fn main() {
    dotenv().ok();
    env_logger::init();

    let pow_mgr = PoWManager::new();
    let pow_mgr_filter = warp::any().map(move || pow_mgr.clone());

    let (queue, rx) = Queue::new();
    let worker_queue = queue.clone();
    thread::spawn(move || {
        worker_main(worker_queue, rx);
    });

    let queue_filter = warp::any().map(move || queue.clone());

    let hashcash_filter = warp::header::<String>("x-hashcash")
        .or(warp::any().map(|| String::new()))
        .unify();

    let mut cache_headers = HeaderMap::new();
    cache_headers.insert(
        "cache-control",
        HeaderValue::from_static("max-age=1, s-maxage=1, stale-while-revalidate, public"),
    );

    let token_route = warp::path("token")
        .and(warp::get())
        .and(pow_mgr_filter.clone())
        .and_then(get_token)
        .with(warp::reply::with::headers(cache_headers.clone()));

    let status_route = warp::path("status")
        .and(warp::get())
        .and(queue_filter.clone())
        .and_then(get_status)
        .with(warp::reply::with::headers(cache_headers.clone()));

    let upload_route = warp::path("upload")
        .and(warp::post())
        .and(pow_mgr_filter.clone())
        .and(hashcash_filter)
        .and(queue_filter.clone())
        .and(warp::multipart::form().max_length(*MAX_FILE_SIZE))
        .and_then(upload);

    let cors = warp::cors()
        .allow_any_origin()
        .allow_headers(vec!["content-type", "x-hashcash"])
        .allow_methods(vec!["GET", "POST"]);

    let router = upload_route
        .or(status_route)
        .or(token_route)
        .with(cors)
        .recover(handle_rejection);

    warp::serve(router).run(([0, 0, 0, 0], 8080)).await;
}

async fn get_token(pow_mgr: PoWManager) -> Result<impl Reply, Rejection> {
    Ok(warp::reply::json(&pow_mgr.get_token()))
}

async fn get_status(queue: Queue) -> Result<impl Reply, Rejection> {
    let worker_state = queue.worker_state.load(Ordering::SeqCst);
    let enqueued = queue.enqueued.load(Ordering::SeqCst);
    let res = QueueStatus {
        enqueued,
        consumed: worker_state / 3,
        fpga: match worker_state % 3 {
            1 => FPGAState::Programming,
            2 => FPGAState::Running,
            _ => FPGAState::Wait,
        },
    };
    Ok(warp::reply::json(&res))
}

async fn upload(
    pow_mgr: PoWManager,
    token: String,
    queue: Queue,
    form: FormData,
) -> Result<impl Reply, Rejection> {
    pow_mgr
        .validate_token(&token)
        .map_err(|e| warp::reject::custom(e))?;

    let parts: Vec<Part> = form
        .try_collect()
        .await
        .map_err(|e| warp::reject::custom(APIError::OperationalError(e.to_string())))?;

    for p in parts {
        if p.name() == "file" {
            let value = p
                .stream()
                .try_fold(Vec::new(), |mut vec, data| {
                    vec.put(data);
                    async move { Ok(vec) }
                })
                .await
                .map_err(|e| warp::reject::custom(APIError::ReadReqError(e.to_string())))?;

            let filename = format!("./files/{}", Uuid::new_v4().to_string());
            tokio::fs::write(&filename, value)
                .await
                .map_err(|e| warp::reject::custom(APIError::WriteFileError(e.to_string())))?;

            let res = queue
                .tx
                .try_send(filename.clone())
                .map_err(|e| warp::reject::custom(APIError::EnqueueError(e.to_string())));
            if let Err(e) = res {
                let _ = tokio::fs::remove_file(&filename)
                    .await
                    .map_err(|e| error!("cannot remove file {:?}: {:?}", filename, e));
                return Err(e);
            }
            let pos = queue.enqueued.fetch_add(1, Ordering::SeqCst);
            return Ok(warp::reply::json(&pos));
        }
    }

    Err(warp::reject::custom(APIError::ReqMissingFile))
}

impl Reject for PoWError {}
impl Reject for APIError {}

async fn handle_rejection(err: Rejection) -> std::result::Result<impl Reply, Infallible> {
    let (code, message) = if err.is_not_found() {
        (StatusCode::NOT_FOUND, "Not Found".to_string())
    } else if let Some(_) = err.find::<warp::reject::PayloadTooLarge>() {
        (StatusCode::BAD_REQUEST, "Payload too large".to_string())
    } else if let Some(e) = err.find::<PoWError>() {
        (StatusCode::BAD_REQUEST, e.to_string())
    } else if let Some(e) = err.find::<APIError>() {
        (
            match e {
                APIError::ReqMissingFile => StatusCode::BAD_REQUEST,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            },
            e.to_string(),
        )
    } else {
        error!("unhandled error: {:?}", err);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal Server Error".to_string(),
        )
    };

    Ok(warp::reply::with_status(message, code))
}
