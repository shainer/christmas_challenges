extern crate bcrypt;

use bcrypt::verify;
use std::io::prelude::*;
use std::fs::File;

pub fn read_file(path: &str) -> String {
    let mut f = File::open(path).expect("File not found.");
    let mut contents = String::new();
    f.read_to_string(&mut contents).expect(
        "Error reading the file contents.",
    );
    contents
}

fn crack_passwords() {
    let mut hashes = [
        "$2y$10$TYau45etgP4173/zx1usm.uO34TXAld/8e0/jKC5b0jHCqs/MZGBi",
        "$2y$10$qQVWugep3jGmh4ZHuHqw8exczy4t8BZ/Jy6H4vnbRiXw.BGwQUrHu",
        "$2y$10$DuZ0T/Qieif009SdR5HD5OOiFl/WJaDyCDB/ztWIM.1koiDJrN5eu",
        "$2y$10$0ClJ1I7LQxMNva/NwRa5L.4ly3EHB8eFR5CckXpgRRKAQHXvEL5oS",
        "$2y$10$LIWMJJgX.Ti9DYrYiaotHuqi34eZ2axl8/i1Cd68GYsYAG02Icwve",
    ].to_vec();

    // The password file has been taken from https://github.com/danielmiessler/SecLists.
    let passwords = read_file("data/10_million_password_list_top_1000.txt");
    for password in passwords.split('\n') {
        if password.is_empty() {
            continue;
        }

        let mut i = 0;
        let mut to_remove: Option<usize> = None;
        for h in &hashes {
            if verify(password, h).unwrap() {
                println!("Found password {} with hash {}", password, h);
                to_remove = Some(i);
            }

            i += 1;
        }

        if to_remove.is_some() {
            hashes.remove(to_remove.unwrap());


            if hashes.is_empty() {
                break;
            }
        }
    }

    if hashes.is_empty() {
        println!("[**] Successfully cracked all hashes.");
    } else {
        println!("[!!] Failed to crack {} hashes.", hashes.len());
    }
}

fn main() {
    crack_passwords();

    // 22 chars = salt, radix-64 encoded
    // 31 chars = resulting hash, radix-64 encoded
    // cost parameter is 10, 2^10 rounds.
    //
    // Nobody else, including canonical OpenBSD, adopted the idea of 2x/2y.
    // This version marker change was limited to crypt_blowfish (the PHP implementation).
    //
    // $2y$10 = bcrypt with 10 rounds.
}
