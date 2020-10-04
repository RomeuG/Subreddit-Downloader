use std::env;

fn main() {
    let args = clap::App::new("reddit-downloader")
        .version("0.1")
        .author("Romeu Vieira <romeu.bizz@gmail.com>")
        .about("Download Reddit threads!")
        .arg(
            clap::Arg::with_name("Output")
                .short("o")
                .long("output")
                .value_name("DIRECTORY")
                .help("Sets output directory")
                .takes_value(true),
        )
        .arg(
            clap::Arg::with_name("Subreddit")
                .short("r")
                .long("subreddit")
                .value_name("SUBREDDIT")
                .help("Sets subreddit")
                .takes_value(true),
        )
        .get_matches();

    let subreddit = args.value_of("Subreddit").unwrap();

    let directory = args.value_of("Output").unwrap();
    let directory_fs = std::fs::metadata(directory).unwrap();

    if !directory_fs.is_dir() {
        println!("Invalid path: not a directory!\n");
        std::process::exit(-1);
    }

    let r_id = env::var("REDDIT_ID").unwrap();
    let r_secret = env::var("REDDIT_SECRET").unwrap();
    let r_user = env::var("REDDIT_USER").unwrap();
    let r_pass = env::var("REDDIT_PASS").unwrap();
    let r_useragent = env::var("REDDIT_USERAGENT").unwrap();

    println!("Hello, world!");
}
