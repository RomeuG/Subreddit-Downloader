use std::env;
use std::error::Error;

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
struct Reddit {
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

    fn check_sleep(&self) {
        println!(
            "Remaining requests: {} | Reset seconds: {}",
            self.remaining_requests, self.reset_seconds
        );

        if self.remaining_requests == 0 {
            println!("Sleeping for {} seconds...", self.reset_seconds);
            std::thread::sleep(std::time::Duration::from_secs(self.reset_seconds as u64));
        }
    }

    fn parse_headers(&mut self, response: &reqwest::blocking::Response) {
        self.remaining_requests = response
            .headers()
            .get("x-ratelimit-remaining")
            .unwrap_or(&reqwest::header::HeaderValue::from_str("0.0").unwrap())
            .to_str()
            .unwrap_or("0.0")
            .to_string()
            .parse::<f32>()
            .unwrap_or(0.0) as i32;

        self.used_requests = response
            .headers()
            .get("x-ratelimit-used")
            .unwrap_or(&reqwest::header::HeaderValue::from_str("0").unwrap())
            .to_str()
            .unwrap_or("0")
            .to_string()
            .parse::<i32>()
            .unwrap_or(0);

        self.reset_seconds = response
            .headers()
            .get("x-ratelimit-reset")
            .unwrap_or(&reqwest::header::HeaderValue::from_str("0").unwrap())
            .to_str()
            .unwrap_or("0")
            .to_string()
            .parse::<i32>()
            .unwrap_or(0);
    }

    pub async fn req_threads(&mut self, outdir: &String, thread_list: Vec<String>) {
        let header_auth = format!(
            "Bearer {}",
            self.access_token.as_ref().unwrap().access_token
        );

        for thread in thread_list {
            self.get_thread(outdir, &thread, &header_auth).await;
        }
    }

    async fn get_thread(&mut self, outdir: &String, thread_name: &String, header_auth: &String) {
        self.check_sleep();

        let url_fmt = format!("https://oauth.reddit.com{}.json", thread_name);
        let url = reqwest::Url::parse(&url_fmt).unwrap();

        let client = reqwest::blocking::Client::new();
        let res = client
            .get(url.clone())
            .header(reqwest::header::USER_AGENT, &self.user_agent)
            .header(reqwest::header::AUTHORIZATION, header_auth)
            .send()
            .unwrap();

        println!("Downloaded {}", url);

        let full_path = generate_full_path(outdir.clone(), get_thread_name(&thread_name));
        println!("Full path: {}", full_path);

        self.parse_headers(&res);

        let response_json: serde_json::Value = res.json().unwrap();
        let pretty_printed = serde_json::to_string_pretty(&response_json).unwrap();

        save_to_file(&full_path, &pretty_printed);
    }

    pub fn req_access_token(&mut self) {
        let url_fmt = format!("https://www.reddit.com/api/v1/access_token?grant_type=password&username={}&password={}", self.user, self.pass);
        let url = reqwest::Url::parse(&url_fmt).unwrap();

        let auth_plain = format!("{}:{}", self.id, self.secret);
        let auth_b64 = base64::encode(auth_plain);
        let header_auth = format!("Basic {}", auth_b64);

        let client = reqwest::blocking::Client::new();
        let res = client
            .post(url)
            .header(reqwest::header::USER_AGENT, &self.user_agent)
            .header(reqwest::header::AUTHORIZATION, &header_auth)
            .send()
            .unwrap();

        let json = res.json::<AccessToken>().unwrap();

        self.access_token = Some(json.clone());
    }

    pub fn req_subreddit(&self) -> Vec<String> {
        let mut thread_url_list: Vec<String> = vec![];

        self.check_sleep();

        let url_fmt = format!("https://oauth.reddit.com/r/{}/.json", self.subreddit);
        let url = reqwest::Url::parse(&url_fmt).unwrap();

        let header_auth = format!(
            "Bearer {}",
            self.access_token.as_ref().unwrap().access_token
        );

        let client = reqwest::blocking::Client::new();
        let res = client
            .get(url)
            .header(reqwest::header::USER_AGENT, &self.user_agent)
            .header(reqwest::header::AUTHORIZATION, &header_auth)
            .send()
            .unwrap()
            .text()
            .unwrap();

        let page = serde_json::from_str::<JsonPage>(&res).unwrap();
        let mut after = page.data.after;

        for permalink in page.data.children {
            thread_url_list.push(permalink.data.permalink.clone());
        }

        while after.is_some() {
            self.check_sleep();

            let next_url_fmt = format!(
                "https://oauth.reddit.com/r/{}/.json?after={}",
                self.subreddit,
                after.unwrap()
            );
            let next_url = reqwest::Url::parse(&next_url_fmt).unwrap();

            let next_client = reqwest::blocking::Client::new();
            let next_res = next_client
                .get(next_url)
                .header(reqwest::header::USER_AGENT, &self.user_agent)
                .header(reqwest::header::AUTHORIZATION, &header_auth)
                .send()
                .unwrap()
                .text()
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

    let mut reddit_ctx = Reddit::new(
        r_id,
        r_secret,
        r_user,
        r_pass,
        r_useragent,
        arg_subreddit.to_string(),
    );

    reddit_ctx.req_access_token();
    let thread_list = reddit_ctx.req_subreddit();
    reddit_ctx.req_threads(&dir_str, thread_list).await;

    Ok(())
}
