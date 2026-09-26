#[tokio::main]
async fn main() {
    let fetcher = aptg::mirror::fetch::MirrorFetcher::new_with_default();
    let suite = "bookworm";

    let deb_path = "/debian/pool/main/a/apt/apt_2.6.1_amd64.deb";
    println!("Fetching with hash validation: {}", deb_path);
    match fetcher.fetch_with_hash_validation(deb_path, suite).await {
        Ok(resp) => println!(
            "Success: status={}, body_len={}",
            resp.status,
            resp.body.len()
        ),
        Err(e) => println!("Hash validation failed: {}", e),
    }
}
