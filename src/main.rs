use std::env;
use std::error::Error;
use std::sync::Arc;
// use std::sync::RwLock;
use parking_lot::RwLock;
use reqwest::Client;

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
struct AccessToken {
    access_token: String,
    token_type: String,
    expires_in: i32,
    scope: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
struct JsonPage {
    data: JsonPageData,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
struct JsonPageData {
    children: Vec<JsonThread>,
    after: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
struct JsonThread {
    data: JsonThreadData,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
struct JsonThreadData {
    title: String,
    permalink: String,
    url: String,
}

#[derive(Debug)]
pub struct Reddit {
    id: String,
    secret: String,
    user: String,
    pass: String,
    user_agent: String,
    remaining_requests: i32,
    reset_seconds: i32,
    used_requests: i32,
    subreddit: String,
    access_token: Option<AccessToken>,
}

impl Reddit {
    pub fn new(
        id: String,
        secret: String,
        user: String,
        pass: String,
        user_agent: String,
        subreddit: String,
    ) -> Self {
        Self {
            id,
            secret,
            user,
            pass,
            user_agent,
            remaining_requests: -1,
            reset_seconds: -1,
            used_requests: -1,
            subreddit,
            access_token: None,
        }
    }

    pub fn get_basic_token(&self) -> String {
        let auth_plain = format!("{}:{}", self.id, self.secret);
        let auth_b64 = base64::encode(auth_plain);

        format!("Basic {}", auth_b64)
    }

    pub fn get_bearer_token(&self) -> String {
        format!(
            "Bearer {}",
            self.access_token.as_ref().unwrap().access_token
        )
    }

    pub fn get_access_token_url(&self) -> String {
        format!(
            "https://www.reddit.com/api/v1/access_token?grant_type=password&username={}&password={}",
            self.user, self.pass
        )
    }

    pub fn get_subreddit_url(&self) -> String {
        format!("https://oauth.reddit.com/r/{}/.json", self.subreddit)
    }

    pub fn get_paginated_url(&self, after: &String) -> String {
        format!(
            "https://oauth.reddit.com/r/{}/.json?after={}",
            self.subreddit, after
        )
    }
}

async fn check_sleep(reddit_ctx: &Arc<RwLock<Reddit>>) {
    let remaining_requests = reddit_ctx.read().remaining_requests;
    let reset_seconds = reddit_ctx.read().reset_seconds;

    println!(
        "Remaining requests: {} | Reset seconds: {}",
        remaining_requests, reset_seconds
    );

    if remaining_requests == 0 {
        println!("Sleeping for {} seconds...", reset_seconds);
        std::thread::sleep(std::time::Duration::from_secs(reset_seconds as u64));
    }
}

fn parse_headers(reddit_ctx: &Arc<RwLock<Reddit>>, response: &reqwest::Response) {
    reddit_ctx.write().remaining_requests = response
        .headers()
        .get("x-ratelimit-remaining")
        .unwrap_or(&reqwest::header::HeaderValue::from_str("0.0").unwrap())
        .to_str()
        .unwrap_or("0.0")
        .to_string()
        .parse::<f32>()
        .unwrap_or(0.0) as i32;

    reddit_ctx.write().used_requests = response
        .headers()
        .get("x-ratelimit-used")
        .unwrap_or(&reqwest::header::HeaderValue::from_str("0").unwrap())
        .to_str()
        .unwrap_or("0")
        .to_string()
        .parse::<i32>()
        .unwrap_or(0);

    reddit_ctx.write().reset_seconds = response
        .headers()
        .get("x-ratelimit-reset")
        .unwrap_or(&reqwest::header::HeaderValue::from_str("0").unwrap())
        .to_str()
        .unwrap_or("0")
        .to_string()
        .parse::<i32>()
        .unwrap_or(0);
}

pub async fn req_threads(
    reddit_ctx: &Arc<RwLock<Reddit>>,
    outdir: &String,
    thread_list: Vec<String>,
) {
    let header_auth = reddit_ctx.read().get_bearer_token();

    for thread in thread_list {
        get_thread(reddit_ctx, outdir, &thread, &header_auth).await;
    }
}

async fn get_thread(
    reddit_ctx: &Arc<RwLock<Reddit>>,
    outdir: &String,
    thread_name: &String,
    header_auth: &String,
) {
    {
        check_sleep(&reddit_ctx).await;
    }

    let url_fmt = format!("https://oauth.reddit.com{}.json", thread_name);
    let url = reqwest::Url::parse(&url_fmt).unwrap();

    let user_agent: String;
    {
        user_agent = reddit_ctx.read().user_agent.clone();
    }

    let client = reqwest::Client::new();
    let res = client
        .get(url.clone())
        .header(reqwest::header::USER_AGENT, user_agent)
        .header(reqwest::header::AUTHORIZATION, header_auth)
        .send()
        .await
        .unwrap();

    println!("Downloaded {}", url);

    let full_path = generate_full_path(outdir.clone(), get_thread_name(&thread_name));
    println!("Full path: {}", full_path);

    parse_headers(&reddit_ctx, &res);

    let response_json: serde_json::Value = res.json().await.unwrap();
    let pretty_printed = serde_json::to_string_pretty(&response_json).unwrap();

    save_to_file(&full_path, &pretty_printed);
}

pub async fn req_access_token(reddit_ctx: &Arc<RwLock<Reddit>>) {
    let res: reqwest::Response;
    {
        let url_fmt = reddit_ctx.read().get_access_token_url();
        let url = reqwest::Url::parse(&url_fmt).unwrap();

        let user_agent = &reddit_ctx.read().user_agent;
        let header_auth = reddit_ctx.read().get_basic_token();

        let client = reqwest::Client::new();
        res = client
            .post(url)
            .header(reqwest::header::USER_AGENT, user_agent)
            .header(reqwest::header::AUTHORIZATION, &header_auth)
            .send()
            .await
            .unwrap();
    }
    let json = res.json::<AccessToken>().await.unwrap();

    reddit_ctx.write().access_token = Some(json.clone());
}

pub async fn req_subreddit(reddit_ctx: &Arc<RwLock<Reddit>>) -> Vec<String> {
    let mut thread_url_list: Vec<String> = vec![];

    check_sleep(&reddit_ctx).await;

    let url_fmt = reddit_ctx.read().get_subreddit_url();
    let url = reqwest::Url::parse(&url_fmt).unwrap();

    let header_auth = reddit_ctx.read().get_bearer_token();
    let user_agent = &reddit_ctx.read().user_agent;

    let client = reqwest::Client::new();
    let res = client
        .get(url)
        .header(reqwest::header::USER_AGENT, user_agent)
        .header(reqwest::header::AUTHORIZATION, &header_auth)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    let page = serde_json::from_str::<JsonPage>(&res).unwrap();
    let mut after = page.data.after;

    for permalink in page.data.children {
        thread_url_list.push(permalink.data.permalink.clone());
    }

    while after.is_some() {
        check_sleep(&reddit_ctx).await;

        let next_url_fmt = reddit_ctx.read().get_paginated_url(&after.unwrap());
        let next_url = reqwest::Url::parse(&next_url_fmt).unwrap();

        let next_client = reqwest::Client::new();
        let next_res = next_client
            .get(next_url)
            .header(reqwest::header::USER_AGENT, user_agent)
            .header(reqwest::header::AUTHORIZATION, &header_auth)
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();

        let next_page = serde_json::from_str::<JsonPage>(&next_res).unwrap();
        after = next_page.data.after;

        for permalink in &next_page.data.children {
            println!("Saving permalink: {}", permalink.data.permalink);
            thread_url_list.push(permalink.data.permalink.clone());
        }

        match &after {
            Some(val) => {
                println!(
                    "After: {} Children: {}\n",
                    val,
                    next_page.data.children.len()
                );
            }
            None => {
                break;
            }
        }
    }

    return thread_url_list;
}

fn get_thread_name(permalink: &String) -> String {
    let mut slash_idx = 0;

    for (i, c) in permalink.bytes().enumerate() {
        if i == permalink.len() - 1 {
            break;
        }

        if c == '/' as u8 {
            slash_idx = i;
        }
    }

    let substring = &permalink[slash_idx + 1..permalink.len() - 1];

    return substring.to_string();
}

fn generate_full_path(dir: String, permalink: String) -> String {
    let mut duplicate = false;
    let mut tries = 0;

    let mut full_path = format!("{}{}.json", dir, permalink);

    if std::path::Path::new(&full_path).exists() {
        duplicate = true;
    }

    while duplicate == true {
        full_path = format!("{}{}_{}.json", dir, permalink, tries);

        if std::path::Path::new(&full_path).exists() {
            duplicate = true;
            tries += 1;
        } else {
            duplicate = false;
        }
    }

    return full_path.to_string();
}

fn save_to_file(dir: &String, text: &String) {
    std::fs::write(dir, text).expect("Unable to write file!");
}

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn Error>> {
    let args = clap::App::new("reddit-downloader")
        .version("1.0")
        .author("Romeu Vieira <romeu.bizz@gmail.com>")
        .about("Download Reddit threads in JSON format")
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

    let r_id = env::var("REDDIT_ID").unwrap();
    let r_secret = env::var("REDDIT_SECRET").unwrap();
    let r_user = env::var("REDDIT_USER").unwrap();
    let r_pass = env::var("REDDIT_PASS").unwrap();
    let r_useragent = env::var("REDDIT_USERAGENT").unwrap();

    let mut reddit_ctx = Arc::new(RwLock::new(Reddit::new(
        r_id,
        r_secret,
        r_user,
        r_pass,
        r_useragent,
        arg_subreddit.to_string(),
    )));

    println!("test0");
    req_access_token(&reddit_ctx.clone()).await;
    println!("test1");
    let thread_list = req_subreddit(&reddit_ctx).await;
    println!("test2");
    req_threads(&reddit_ctx, &dir_str, thread_list).await;

    Ok(())
}
