use std::{fs::File, io::Read, path::PathBuf};

#[test]
fn test_loginitems_file() {
    let mut test_location = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_location.push("tests/test_data/loginitem.bookmark");
    let mut open_results = File::open(test_location).unwrap();
    let mut buffer = Vec::new();
    let bytes_read = open_results.read_to_end(&mut buffer).unwrap();

    assert_eq!(bytes_read, 756);

    let bookmark_data = macos_bookmarks::parser::parse_bookmark(&buffer).unwrap();
    let creation = 665473989.0;
    let path = ["Applications", "Syncthing.app"];
    let cnid = [103, 706090];
    let volume_path = "/";
    let volume_url = "file:///";
    let volume_name = "Macintosh HD";
    let volume_uuid = "0A81F3B1-51D9-3335-B3E3-169C3640360D";
    let volume_size = 160851517440;
    let volume_creation = 241134516.0;
    let volume_flags = [4294967425, 4294972399, 0];
    let volume_root = true;
    let localized_name = "Syncthing";
    let extension = "64cb7eaa9a1bbccc4e1397c9f2a411ebe539cd29;00000000;00000000;0000000000000020;com.apple.app-sandbox.read-write;01;01000004;00000000000ac62a;/applications/syncthing.app\u{0}";
    let target_flags = [2, 15, 0];
    let folder_index = 0;
    let uid = 0;
    let username = String::new();
    let creation_options = 0;
    let is_executable = false;

    assert_eq!(bookmark_data.creation, creation);
    assert_eq!(bookmark_data.path, path);
    assert_eq!(bookmark_data.cnid_path, cnid);
    assert_eq!(bookmark_data.volume_path, volume_path);
    assert_eq!(bookmark_data.volume_url, volume_url);
    assert_eq!(bookmark_data.volume_name, volume_name);
    assert_eq!(bookmark_data.volume_uuid, volume_uuid);
    assert_eq!(bookmark_data.volume_creation, volume_creation);
    assert_eq!(bookmark_data.volume_size, volume_size);
    assert_eq!(bookmark_data.volume_flag, volume_flags);
    assert_eq!(bookmark_data.volume_root, volume_root);
    assert_eq!(bookmark_data.localized_name, localized_name);
    assert_eq!(bookmark_data.security_extension, extension);
    assert_eq!(bookmark_data.target_flags, target_flags);
    assert_eq!(bookmark_data.folder_index, folder_index);
    assert_eq!(bookmark_data.uid, uid);
    assert_eq!(bookmark_data.username, username);
    assert_eq!(bookmark_data.creation_options, creation_options);
    assert_eq!(bookmark_data.is_executable, is_executable);
}

#[test]
fn test_safari_downloads_bookmark_file() {
    let mut test_location = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_location.push("tests/test_data/downloads.bookmark");
    let mut open_results = File::open(test_location).unwrap();
    let mut buffer = Vec::new();
    let bytes_read = open_results.read_to_end(&mut buffer).unwrap();

    assert_eq!(bytes_read, 716);

    let bookmark = macos_bookmarks::parser::parse_bookmark(&buffer).unwrap();

    let app_path_len = 4;
    let app_path = [
        "Users",
        "puffycid",
        "Downloads",
        "powershell-7.2.4-osx-x64.pkg",
    ];
    let cnid_path = [21327, 360459, 360510, 37602008];
    let volume_path = "/";
    let volume_url = "file:///";
    let volume_name = "Macintosh HD";
    let volume_uuid = "96FB41C0-6CE9-4DA2-8435-35BC19C735A3";
    let volume_size = 2000662327296;
    let volume_flag = [4294967425, 4294972399, 0];
    let volume_root = true;
    let localized_name = String::new();
    let target_flags = [1, 15, 0];
    let username = "puffycid";
    let folder_index = 2;
    let uid = 501;
    let creation_options = 671094784;
    let security_extension = String::new();

    let cnid_path_len = 4;
    let target_creation = 677388100.0747445;
    let volume_creation = 667551907.0;
    let target_flags_len = 3;

    assert_eq!(bookmark.path.len(), app_path_len);
    assert_eq!(bookmark.cnid_path.len(), cnid_path_len);
    assert_eq!(bookmark.creation, target_creation);
    assert_eq!(bookmark.volume_creation, volume_creation);
    assert_eq!(bookmark.target_flags.len(), target_flags_len);

    assert_eq!(bookmark.path, app_path);
    assert_eq!(bookmark.cnid_path, cnid_path);
    assert_eq!(bookmark.volume_path, volume_path);
    assert_eq!(bookmark.volume_url, volume_url);
    assert_eq!(bookmark.volume_name, volume_name);
    assert_eq!(bookmark.volume_uuid, volume_uuid);
    assert_eq!(bookmark.volume_size, volume_size);
    assert_eq!(bookmark.volume_flag, volume_flag);
    assert_eq!(bookmark.volume_root, volume_root);
    assert_eq!(bookmark.localized_name, localized_name);
    assert_eq!(bookmark.target_flags, target_flags);
    assert_eq!(bookmark.username, username);
    assert_eq!(bookmark.folder_index, folder_index);
    assert_eq!(bookmark.uid, uid);
    assert_eq!(bookmark.creation_options, creation_options);
    assert_eq!(bookmark.security_extension, security_extension);
}

#[test]
#[should_panic(expected = "BadHeader")]
fn test_bad_sig() {
    let mut test_location = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_location.push("tests/test_data/bad_header.bookmark");
    let mut open_results = File::open(test_location).unwrap();
    let mut buffer = Vec::new();
    let bytes_read = open_results.read_to_end(&mut buffer).unwrap();

    assert_eq!(bytes_read, 756);

    let _ = macos_bookmarks::parser::parse_bookmark(&buffer).unwrap();
}

#[test]
#[should_panic(expected = "BadBookmarkData")]
fn test_bad_content() {
    let mut test_location = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_location.push("tests/test_data/bad_content.bookmark");
    let mut open_results = File::open(test_location).unwrap();
    let mut buffer = Vec::new();
    let bytes_read = open_results.read_to_end(&mut buffer).unwrap();

    assert_eq!(bytes_read, 377);

    let _ = macos_bookmarks::parser::parse_bookmark(&buffer).unwrap();
}
