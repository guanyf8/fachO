mod modify_dylib;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        eprintln!("Usage: {} <dylib_path> <old_ordinal> <new_ordinal>", args[0]);
        return;
    }
    let file = args[1].clone();
    let old_ordinal: i32 = args[2].parse().expect("Invalid old ordinal");
    let new_ordinal: i32 = args[3].parse().expect("Invalid new ordinal");

    modify_dylib::modify_dylib(file, old_ordinal, new_ordinal);
}
