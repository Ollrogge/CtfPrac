#![feature(get_mut_unchecked)]

use std::collections::BTreeMap;
use std::io::{self, Read, Stdin, Stdout, Write, Cursor};
use std::iter::RepeatN;
use std::rc::Rc;

struct InputHelper<R: Read> {
    stdin: R,
    stdout: Stdout,
    buf: Vec<u8>,
}

impl<R: Read> InputHelper<R> {
    fn with_capacity(cap: usize, inp: R) -> Self {
        let stdout = io::stdout();
        Self {
            stdin: inp,
            stdout,
            buf: vec![0u8; cap],
        }
    }

    /*
    fn ask(&mut self, msg: &str) -> &[u8] {
        self.stdout.write(msg.as_bytes()).unwrap();
        self.stdout.write(b"\n").unwrap();
        let len = self.stdin.read(&mut self.buf).unwrap();
        &self.buf[..len].trim_ascii()
    }
    */

    fn ask(&mut self, msg: &str) -> &[u8] {
        self.stdout.write(msg.as_bytes()).unwrap();
        self.stdout.write(b"\n").unwrap();

        let mut len = 0;
        loop {
            // Read one byte at a time
            let num_bytes = self.stdin.read(&mut self.buf[len..len + 1]).unwrap();

            // Check for EOF
            if num_bytes == 0 {
                if len == 0 {
                    std::process::exit(0);
                } else {
                    break;
                }
            }

            len += num_bytes;

            // Stop reading if we encounter a newline or buffer is full
            if self.buf[len - 1] == b'\n' || len == self.buf.len() {
                break;
            }
        }

        &self.buf[..len].trim_ascii()
    }

    /*

     fn ask(&mut self, msg: &str) -> &[u8] {
        self.stdout.write(msg.as_bytes()).unwrap();
        self.stdout.write(b"\n").unwrap();

        let mut len = 0;
        while len == 0 {
            // Read data byte-by-byte until we get a full line or buffer is full
            let num_bytes = self.stdin.read(&mut self.buf[len..len + 1]).unwrap();
            len += num_bytes;

            if len == 0 {
                std::process::exit(0);
            }

            // Stop reading if we encounter a newline
            if self.buf[len - 1] == b'\n' || len == self.buf.len() {
                break;
            }
        }

        //println!("Read: {:?}", &self.buf[..len]);

        &self.buf[..len].trim_ascii()
    }
    */


    fn ask_num(&mut self, msg: &str) -> i64 {
        let buf = self.ask(msg);
        let ret= std::str::from_utf8(buf);
        if ret.is_err() {
            std::process::exit(0);
        }
        let ret = ret.unwrap().parse();
        if ret.is_err() {
            std::process::exit(0);
        }

        ret.unwrap()
    }
}

#[derive(Debug)]
struct Exercise {
    name: Vec<u8>,
    description: Vec<u8>,
}

#[derive(Debug, Clone)]
struct Workout {
    exercises: Vec<RepeatN<Rc<Exercise>>>,
}

fn chall<R: Read>(inp: R) {
    let mut exercises = BTreeMap::new();
    let mut workouts = Vec::new();

    let mut input = InputHelper::with_capacity(0x100, inp);

    println!("Welcome to your personal training helper! Here are your options:");
    loop {
        println!("1. : add a new exercise to your portfolio");
        println!("2. : plan a new workout");
        println!("3. : start a training session");
        println!("4. : edit an exercise");
        println!("5. : exit the app");

        let line = input.ask("Choose an option: ").trim_ascii();
        match &*line {
            b"1" => {
                let name = input.ask("What's the name of your exercise? ").to_owned();

                let description = input
                    .ask("what is the description of your exercise? ")
                    .to_owned();

                let name2 = name.clone();
                let exercise: Exercise = Exercise { name, description };
                exercises.insert(name2, Rc::new(exercise));
                println!("Exercise added!");
            }
            b"2" => {
                let num_exercises = input.ask_num("How many exercises should your workout have? ");
                let mut workout = Workout {
                    exercises: Vec::new(),
                };

                for _ in 0..num_exercises {
                    let name = input.ask("Enter the name of the exercise: ");
                    if let Some(exercise) = exercises.get(name) {
                        let num_repetitions =
                            input.ask_num("How many times should your exercise be repeated? ");
                        workout.exercises.push(std::iter::repeat_n(
                            Rc::clone(exercise),
                            num_repetitions as usize,
                        ));
                    } else {
                        println!("No exercise found with that name.");
                    }
                }

                println!("Your workout has id {}", workouts.len());
                workouts.push(workout);
            }
            b"3" => {
                let id = input.ask_num("what's the id of your workout? ");

                if id as usize >= workouts.len() {
                    std::process::exit(0);
                }

                let workout = &workouts[id as usize];

                for exercise in workout.exercises.iter().cloned() {
                    for ex in exercise {
                        println!("{:?} - {:?}", ex.name, ex.description); // pls  help, this looks weird :(
                    }
                }
            }
            b"4" => {
                let name = input.ask("Enter the name of the exercise you want to edit: ");
                if let Some(exercise) = exercises.get_mut(name) {
                    let description = input.ask("Enter the new description: ");
                    if description.len() != exercise.description.len() {
                        std::process::exit(0);
                    }
                    unsafe {
                        Rc::get_mut_unchecked(exercise)
                            .description
                            .copy_from_slice(description)
                    }
                    println!("Exercise updated!");
                } else {
                    println!("No exercise found with that name.");
                }
            }
            b"5" => break,
            _ => break,
        }
    }
}

fn main() {
    ziggy::fuzz!(|data: &[u8]| {

        let cursor = Cursor::new(data);
        chall(cursor);
    });
}
