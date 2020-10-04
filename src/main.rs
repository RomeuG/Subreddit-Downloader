use std::env;

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
struct AccessToken {
    access_token: String,
    token_type: String,
    expires_in: i32,
    scope: String,
}

#[derive(Debug)]
struct Reddit {
    id: String,
    secret: String,
    user: String,
    pass: String,
    user_agent: String,
    remaining_requests: i32,
    reset_seconds: i32,
    used_requests: i32,
    access_token: Option<AccessToken>,
}

impl Reddit {
    pub fn new(id: String, secret: String, user: String, pass: String, user_agent: String) -> Self {
        Self {
            id,
            secret,
            user,
            pass,
            user_agent,
            remaining_requests: -1,
            reset_seconds: -1,
            used_requests: -1,
            access_token: None,
        }
    }

    pub fn req_access_token(&mut self) {
        let url_fmt = format!("https://www.reddit.com/api/v1/access_token?grant_type=password&username={}&password={}", self.user, self.pass);
        let url = reqwest::Url::parse(&url_fmt).unwrap();

        // authorization stuff
        let auth_plain = format!("{}:{}", self.id, self.secret);
        let auth_b64 = base64::encode(auth_plain);
        let header_auth = format!("Basic {}", auth_b64);

        let client = reqwest::blocking::Client::new();
        let res = client
            .post(url)
            .header(reqwest::header::USER_AGENT, &self.user_agent)
            .header(reqwest::header::AUTHORIZATION, &header_auth)
            .send()
            .unwrap()
            .json::<AccessToken>()
            .unwrap();

        self.access_token = Some(res.clone());
    }
}

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

    let arg_subreddit = args.value_of("Subreddit").unwrap();

    let arg_directory = args.value_of("Output").unwrap();
    let dir_metadata = std::fs::metadata(arg_directory).unwrap();

    if !dir_metadata.is_dir() {
        println!("Invalid path: not a directory!\n");
        std::process::exit(-1);
    }

    let dir_str: String;
    if !arg_directory.ends_with("/") {
        dir_str = format!("{}/", arg_directory);
    } else {
        dir_str = String::from(arg_directory);
    }

    println!("Final directory str: {}", dir_str);

    let r_id = env::var("REDDIT_ID").unwrap();
    let r_secret = env::var("REDDIT_SECRET").unwrap();
    let r_user = env::var("REDDIT_USER").unwrap();
    let r_pass = env::var("REDDIT_PASS").unwrap();
    let r_useragent = env::var("REDDIT_USERAGENT").unwrap();

    let mut reddit_ctx = Reddit::new(r_id, r_secret, r_user, r_pass, r_useragent);
    reddit_ctx.req_access_token();

    println!("Hello, world!");
}
