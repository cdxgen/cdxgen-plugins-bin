struct Connection;

struct Frame(String);

struct Command {
    frame: Frame,
}

impl Connection {
    fn new() -> Self {
        Self
    }

    fn read_frame(&mut self) -> Frame {
        Frame("request".to_string())
    }

    fn write_frame(&mut self, frame: &Frame) {
        let _ = &frame.0;
    }
}

impl Command {
    fn from_frame(frame: Frame) -> Self {
        Self { frame }
    }

    fn apply(self, connection: &mut Connection) {
        connection.write_frame(&self.frame);
    }
}

fn main() {
    let mut connection = Connection::new();
    let frame = connection.read_frame();
    let command = Command::from_frame(frame);
    command.apply(&mut connection);
}
