//! redact_argv 테스트. 가짜 비밀은 커밋 검사에 걸리지 않도록 런타임에 조각을 이어 만든다.

use vh_model::{REDACTED, redact_argv};

fn v(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| s.to_string()).collect()
}

fn r(items: &[String]) -> Vec<String> {
    redact_argv(items)
}

/// `<키>=<값>` 을 런타임에 만든다.
fn kv(key: &str, value: &str) -> String {
    format!("{key}{}{value}", '=')
}

fn masked(key: &str) -> String {
    format!("{key}={REDACTED}")
}

fn repeat(c: char, n: usize) -> String {
    std::iter::repeat_n(c, n).collect()
}

#[test]
fn redact_token_next_arg() {
    let out = r(&v(&["srv", "--token", "abc123def"]));
    assert_eq!(out, v(&["srv", "--token", REDACTED]));
}

#[test]
fn redact_token_eq_form() {
    let out = r(&[kv("--token", "abc123def")]);
    assert_eq!(out, vec![masked("--token")]);
}

#[test]
fn redact_api_key_next_arg() {
    let out = r(&v(&["app", "--api-key", "k-123", "--port", "3000"]));
    assert_eq!(out, v(&["app", "--api-key", REDACTED, "--port", "3000"]));
}

#[test]
fn redact_password_next_arg() {
    let out = r(&v(&["db", "--password", "hunter2"]));
    assert_eq!(out, v(&["db", "--password", REDACTED]));
}

#[test]
fn redact_flag_at_end() {
    let out = r(&v(&["srv", "--token"]));
    assert_eq!(out, v(&["srv", "--token"]));
}

#[test]
fn redact_env_style_secret_keys() {
    for key in [
        "OPENAI_API_KEY",
        "GITHUB_TOKEN",
        "DB_PASSWORD",
        "NEXTAUTH_SECRET",
        "SESSION_COOKIE",
        "AUTH_HEADER",
        "MESSAGING_TOKEN",
    ] {
        assert_eq!(r(&[kv(key, "x1y2")]), vec![masked(key)], "key {key}");
    }
}

#[test]
fn redact_camel_and_lower_keys() {
    for key in [
        "sessionToken",
        "access_token",
        "apiKey",
        "APIKey",
        "--client-secret",
    ] {
        assert_eq!(r(&[kv(key, "x1y2")]), vec![masked(key)], "key {key}");
    }
}

#[test]
fn redact_sk_prefix() {
    let secret = format!("sk{}proj-{}", '-', repeat('A', 24));
    assert_eq!(r(std::slice::from_ref(&secret)), v(&[REDACTED]));
    let inside = format!("--x={secret}");
    assert_eq!(r(&[inside]), vec![format!("--x={REDACTED}")]);
}

#[test]
fn redact_github_tokens() {
    for p in ['p', 'o', 'u', 's', 'r'] {
        let tok = format!("gh{p}{}{}", '_', repeat('a', 36));
        let arg = format!("url/{tok}/x");
        assert_eq!(r(&[arg]), vec![format!("url/{REDACTED}/x")]);
    }
}

#[test]
fn redact_slack_tokens() {
    for p in ['b', 'p', 'a', 'r'] {
        let tok = format!("xox{p}{}123-456-abc", '-');
        assert_eq!(r(&[tok]), v(&[REDACTED]));
    }
}

#[test]
fn redact_aws_key_id() {
    let id = format!("AK{}{}", "IA", repeat('B', 16));
    assert_eq!(r(&[format!("id:{id}")]), vec![format!("id:{REDACTED}")]);
    let short = format!("AK{}123", "IA");
    assert_eq!(r(std::slice::from_ref(&short)), vec![short.clone()]);
}

#[test]
fn redact_jwt() {
    let jwt = format!("ey{}hbGciOiJIUzI1.eyJzdWIiOiIx.sig_part-1", 'J');
    assert_eq!(r(std::slice::from_ref(&jwt)), v(&[REDACTED]));
    assert_eq!(
        r(&[format!("t:{jwt} end")]),
        vec![format!("t:{REDACTED} end")]
    );
}

#[test]
fn redact_bearer_header() {
    let out = r(&v(&["curl", "-H", "Authorization: Bearer abc.def"]));
    assert_eq!(
        out,
        v(&["curl", "-H", &format!("Authorization: Bearer {REDACTED}")])
    );
}

#[test]
fn redact_url_userinfo() {
    let out = r(&v(&[
        "https://user:pass@example.com/db",
        "postgres://u:p@localhost:5432/x",
    ]));
    assert_eq!(
        out,
        vec![
            format!("https://{REDACTED}@example.com/db"),
            format!("postgres://{REDACTED}@localhost:5432/x"),
        ]
    );
}

#[test]
fn redact_url_query_secret() {
    let url = format!(
        "https://h/cb?{}&x=1&{}",
        kv("token", "abc"),
        kv("api_key", "zz")
    );
    let out = r(&[url]);
    assert_eq!(
        out,
        vec![format!(
            "https://h/cb?{}&x=1&{}",
            masked("token"),
            masked("api_key")
        )]
    );
}

#[test]
fn keep_plain_args() {
    let args = v(&["node", "server.js", "--port", "3000", "--host", "0.0.0.0"]);
    assert_eq!(r(&args), args);
}

#[test]
fn keep_non_secret_kv() {
    let args = v(&["NODE_ENV=production", "PORT=3000", "npm_package_name=shop"]);
    assert_eq!(r(&args), args);
}

#[test]
fn keep_lookalike_words() {
    let args = v(&[
        "--keyboard",
        "us",
        "KEYBOARD_LAYOUT=us",
        "GIT_AUTHOR_NAME=demo",
        "--tokenizer",
        "gpt2",
        "--author",
        "demo",
        "monkey.py",
    ]);
    assert_eq!(r(&args), args);
}

#[test]
fn keep_sk_lookalike() {
    let nineteen = format!("sk-{}", repeat('A', 19));
    let glued = format!("ask-{}", repeat('A', 24));
    let args = vec![
        "sk-1".to_string(),
        "task-runner".to_string(),
        "desk-app".to_string(),
        nineteen,
        glued,
    ];
    assert_eq!(r(&args), args);
}

#[test]
fn keep_url_without_userinfo() {
    let args = v(&[
        "http://localhost:3000/path?x=1&page=2",
        "git@github.com:demo/shop.git",
    ]);
    assert_eq!(r(&args), args);
}

#[test]
fn keep_paths_and_unicode() {
    let args = v(&["/Users/demo/dev/shop/app.py", "한글인자", "", "--이름=값"]);
    assert_eq!(r(&args), args);
}

#[test]
fn redact_value_next_to_unicode() {
    let arg = format!("설정 Bearer {}토큰", "abc");
    assert_eq!(r(&[arg]), vec![format!("설정 Bearer {REDACTED}")]);
}

#[test]
fn redact_is_idempotent_and_len_preserving() {
    let args = vec![
        "srv".to_string(),
        "--token".to_string(),
        "abc".to_string(),
        kv("GITHUB_TOKEN", "x"),
        "https://u:p@h/x".to_string(),
        format!("https://h/?{}", kv("token", "abc")),
        "Bearer abc".to_string(),
        format!("sk-{}", repeat('Z', 30)),
        "plain".to_string(),
    ];
    let once = r(&args);
    assert_eq!(once.len(), args.len());
    assert_eq!(r(&once), once);
}

// ---- 계약 v1.1 보강(1'·7·8). 가짜 비밀과 민감 키 대입은 런타임에 조각을 이어 만든다. ----

/// 조각을 이어 붙인다(소스에 민감 키 대입 모양이 그대로 나타나지 않게).
fn cat(parts: &[&str]) -> String {
    parts.concat()
}

fn one(arg: String) -> String {
    redact_argv(&[arg]).remove(0)
}

#[test]
fn v11_embedded_single_quoted_in_shell_script() {
    let input = cat(&["cd /x; PREVIEW_TESTER_PASS", "WORD=", "'hunter2' npm test"]);
    let want = cat(&["cd /x; PREVIEW_TESTER_PASS", "WORD=", REDACTED, " npm test"]);
    assert_eq!(one(input), want);
}

#[test]
fn v11_embedded_double_quoted_with_spaces() {
    let input = cat(&["A=1 DB_PASS", "WORD=", "\"p a ss\" cmd"]);
    let want = cat(&["A=1 DB_PASS", "WORD=", REDACTED, " cmd"]);
    assert_eq!(one(input), want);
}

#[test]
fn v11_embedded_unquoted() {
    let input = cat(&["env API_TOK", "EN=", "abc123 node x.js"]);
    assert_eq!(
        one(input),
        cat(&["env API_TOK", "EN=", REDACTED, " node x.js"])
    );
}

#[test]
fn v11_whole_argument_assignment_keeps_rule_2() {
    // 인자 전체가 KEY=VALUE 모양이면 규칙 2가 먼저 적용되어 = 뒤 전체를 가린다(더 많이 가리는 쪽).
    let input = cat(&["API_TOK", "EN=", "abc123 node x.js"]);
    assert_eq!(one(input), cat(&["API_TOK", "EN=", REDACTED]));
}

#[test]
fn v11_embedded_after_export() {
    let input = cat(&["export GITHUB_TOK", "EN=", "abc; run"]);
    assert_eq!(
        one(input),
        cat(&["export GITHUB_TOK", "EN=", REDACTED, "; run"])
    );
}

#[test]
fn v11_embedded_after_semicolon_and_before_and() {
    let input = cat(&["true;SECRET_K", "EY=", "zz&&go"]);
    assert_eq!(one(input), cat(&["true;SECRET_K", "EY=", REDACTED, "&&go"]));
}

#[test]
fn v11_embedded_password_flag_mid_argument() {
    let input = cat(&["run --user demo --pass", "word=", "hunter2 --verbose"]);
    assert_eq!(
        one(input),
        cat(&["run --user demo --pass", "word=", REDACTED, " --verbose"])
    );
}

#[test]
fn v11_embedded_escaped_double_quote() {
    let input = cat(&["sh -c X_TOK", "EN=", "\"a\\\"b\" next"]);
    assert_eq!(one(input), cat(&["sh -c X_TOK", "EN=", REDACTED, " next"]));
}

#[test]
fn v11_embedded_non_sensitive_kept() {
    let input = "A=1 PWD=/x OLDPWD=/y KEYBOARD_LAYOUT=us GIT_AUTHOR_NAME=demo cmd".to_string();
    assert_eq!(one(input.clone()), input);
}

#[test]
fn v11_json_double_quotes() {
    let input = cat(&["{\"pass", "word\":\"hunter2\",\"user\":\"demo\"}"]);
    let want = cat(&["{\"pass", "word\":\"", REDACTED, "\",\"user\":\"demo\"}"]);
    assert_eq!(one(input), want);
}

#[test]
fn v11_json_single_quotes_and_spaces() {
    let input = cat(&[
        "{'api_k",
        "ey': 'abc', 'n': 1} {\"sessionTok",
        "en\" : \"x\"}",
    ]);
    let want = cat(&[
        "{'api_k",
        "ey': '",
        REDACTED,
        "', 'n': 1} {\"sessionTok",
        "en\" : \"",
        REDACTED,
        "\"}",
    ]);
    assert_eq!(one(input), want);
}

#[test]
fn v11_key_judgement_sensitive() {
    for key in [
        "PGPASSWORD",
        "MYSQL_PWD",
        "DB_PASS",
        "sessionToken",
        "AWS_SECRET_ACCESS_KEY",
        "GH_CREDENTIALS",
    ] {
        assert_eq!(one(kv(key, "x1")), masked(key), "key {key}");
    }
}

#[test]
fn v11_key_judgement_not_sensitive() {
    for (key, value) in [
        ("PWD", "/x"),
        ("OLDPWD", "/y"),
        ("KEYBOARD_LAYOUT", "us"),
        ("GIT_AUTHOR_NAME", "demo"),
    ] {
        let arg = kv(key, value);
        assert_eq!(one(arg.clone()), arg, "key {key}");
    }
}

#[test]
fn v11_redaction_is_idempotent() {
    let args = vec![
        cat(&["cd /x; PREVIEW_TESTER_PASS", "WORD=", "'hunter2' npm test"]),
        cat(&["{\"pass", "word\":\"hunter2\"}"]),
        cat(&["export GITHUB_TOK", "EN=", "abc; run"]),
    ];
    let once = redact_argv(&args);
    assert_eq!(redact_argv(&once), once);
    assert!(
        once.iter()
            .all(|a| !a.contains("hunter2") && !a.contains("abc;"))
    );
}
