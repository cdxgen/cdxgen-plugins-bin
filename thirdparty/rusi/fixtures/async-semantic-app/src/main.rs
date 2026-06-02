use std::future::Future;
use std::pin::Pin;
use std::sync::{mpsc, Arc, Mutex};
use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

fn noop_raw_waker() -> RawWaker {
    fn clone(_: *const ()) -> RawWaker { noop_raw_waker() }
    fn wake(_: *const ()) {}
    fn wake_by_ref(_: *const ()) {}
    fn drop(_: *const ()) {}
    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, wake, wake_by_ref, drop);
    RawWaker::new(std::ptr::null(), &VTABLE)
}

fn block_on<F: Future>(future: F) -> F::Output {
    let waker = unsafe { Waker::from_raw(noop_raw_waker()) };
    let mut context = Context::from_waker(&waker);
    let mut future = Box::pin(future);
    loop {
        match Pin::new(&mut future).poll(&mut context) {
            Poll::Ready(value) => return value,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

struct Executor<F>(F);
impl<F: FnOnce(String)> Executor<F> {
    fn execute(self, value: String) {
        (self.0)(value)
    }
}

async fn load_secret() -> String {
    std::env::var("APP_CMD")
        .map(|value| value.to_string())
        .and_then(|value| Ok::<String, std::env::VarError>(value))
        .unwrap_or_else(|_| "echo".to_string())
}

async fn dispatch(value: String) {
    let boxed = Arc::new(Mutex::new(Some(value)));
    let (tx, rx) = mpsc::channel();
    let for_task = boxed.clone();
    let join = std::thread::spawn(move || {
        let payload = for_task.lock().unwrap().take().unwrap();
        tx.send(payload).unwrap();
    });
    join.join().unwrap();

    let payload = rx.recv().unwrap();
    let callable = Executor(|cmd: String| {
        let _ = std::process::Command::new(cmd).arg("semantic").status();
    });
    callable.execute(payload);
}

fn main() {
    let secret = block_on(load_secret());
    block_on(dispatch(secret));
}
