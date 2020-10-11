Subreddit Downloader
====================

This program is meant to replace [https://github.com/RomeuG/Reddit-Downloader] and can be used to archive subreddits within its API limits (~1000 most recent threads).

Usage
=====

```
subreddit-downloader 1.0
Romeu Vieira <romeu.bizz@gmail.com>
Download Reddit threads!

USAGE:
    subreddit-downloader [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -o, --output <DIRECTORY>       Sets output directory
    -r, --subreddit <SUBREDDIT>    Sets subreddit
```

Example of downloading the most ~1000 recent threads from Rust Subreddit into `/home/romeu/rust_subreddit` folder:

```
$ subreddit-downloader -r rust -o /home/romeu/rust_subreddit
```

If the command is ran multiple times to the same directory, duplicates will be generated.
To delete the duplicates and to actually keep the most up to date JSON of the threads, you just run the script in the `scripts` directory:

```
$ python3 scripts/duplicate_remover.py OUTPUT_DIR
```

Configuration
=============

Configuration is made entirely through the following self-explanatory Environment Variables:

- `REDDIT_ID`
- `REDDIT_SECRET`
- `REDDIT_USER`
- `REDDIT_PASS`
- `REDDIT_USERAGENT`