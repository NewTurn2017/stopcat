use stopcat_model::display_path;

#[test]
fn display_path_home_exact() {
    assert_eq!(display_path("/Users/demo", "/Users/demo"), "~");
}

#[test]
fn display_path_under_home() {
    assert_eq!(
        display_path("/Users/demo/dev/shop", "/Users/demo"),
        "~/dev/shop"
    );
    assert_eq!(
        display_path("/Users/demo/dev/shop", "/Users/demo/"),
        "~/dev/shop"
    );
}

#[test]
fn display_path_prefix_boundary() {
    assert_eq!(
        display_path("/Users/demo2/x", "/Users/demo"),
        "/Users/demo2/x"
    );
}

#[test]
fn display_path_outside_or_empty_home() {
    assert_eq!(
        display_path("/private/tmp/x", "/Users/demo"),
        "/private/tmp/x"
    );
    assert_eq!(display_path("/Users/demo/x", ""), "/Users/demo/x");
    assert_eq!(display_path("/Users/demo/x", "/"), "/Users/demo/x");
}
