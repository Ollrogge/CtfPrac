#![feature(get_mut_unchecked)]

use std::collections::BTreeMap;
use std::io::{self, Read, Stdin, Stdout, Write};
use std::iter::RepeatN;
use std::rc::Rc;

struct InputHelper {
    stdin: Stdin,
    stdout: Stdout,
    buf: Vec<u8>,
}

impl InputHelper {
    fn with_capacity(cap: usize) -> Self {
        let stdin = io::stdin();
        let stdout = io::stdout();
        Self {
            stdin,
            stdout,
            buf: vec![0u8; cap],
        }
    }

    fn ask(&mut self, msg: &str) -> &[u8] {
        self.stdout.write(msg.as_bytes()).unwrap();
        self.stdout.write(b"\n").unwrap();
        let len = self.stdin.read(&mut self.buf).unwrap();
        &self.buf[..len].trim_ascii()
    }

    fn ask_num(&mut self, msg: &str) -> i64 {
        let buf = self.ask(msg);
        std::str::from_utf8(buf).unwrap().parse().unwrap()
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

fn main() {
    let mut exercises = BTreeMap::new();
    let mut workouts = Vec::new();

    let mut input = InputHelper::with_capacity(0x100);

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
            _ => println!("That was not a valid option"),
        }
    }
}
