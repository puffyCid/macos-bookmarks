use std::{fs, path::PathBuf};

#[test]
// Test bookmark found in Apple LoginItems
fn test_loginitems_file() {
    let mut test_location = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_location.push("tests/test_data/loginitem.bookmark");
    let buffer = fs::read(test_location).unwrap();

    assert_eq!(buffer.len(), 756);

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

    let extension_ro = String::new();

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
    assert_eq!(bookmark_data.security_extension_rw, extension);
    assert_eq!(bookmark_data.target_flags, target_flags);
    assert_eq!(bookmark_data.folder_index, folder_index);
    assert_eq!(bookmark_data.uid, uid);
    assert_eq!(bookmark_data.username, username);
    assert_eq!(bookmark_data.creation_options, creation_options);
    assert_eq!(bookmark_data.is_executable, is_executable);
    assert_eq!(bookmark_data.security_extension_ro, extension_ro);
    assert_eq!(bookmark_data.file_ref_flag, false);
}

#[test]
// Test a bookmark created by PoisonApple https://github.com/CyborgSecurity/PoisonApple
fn test_poisonapple() {
    let mut test_location = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_location.push("tests/test_data/poisonapple.bookmark");
    let buffer = fs::read(test_location).unwrap();

    assert_eq!(buffer.len(), 1020);

    let bookmark_data = macos_bookmarks::parser::parse_bookmark(&buffer).unwrap();
    let creation = 678248174.9226916;
    let path = [
        "Users",
        "sur",
        "Library",
        "Python",
        "3.8",
        "lib",
        "python",
        "site-packages",
        "poisonapple",
        "auxiliary",
        "testing.app",
    ];
    let cnid = [
        12884925338,
        12884935193,
        12884935201,
        12885139219,
        12885139220,
        12885139221,
        12885139222,
        12885139223,
        12885139514,
        12885139519,
        12885142308,
    ];
    let volume_path = "/";
    let volume_url = "file:///";
    let volume_name = "Macintosh HD";
    let volume_uuid = "0A81F3B1-51D9-3335-B3E3-169C3640360D";
    let volume_size = 85555372032;
    let volume_creation = 599558400.0;
    let volume_flags = [4294967425, 4294972399, 0];
    let volume_root = true;
    let localized_name = "testing";
    let extension = String::new();
    let target_flags = [530, 543, 538];
    let folder_index = 9;
    let uid = 501;
    let username = "sur";
    let creation_options = 536870912;
    let is_executable = true;

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
    assert_eq!(bookmark_data.security_extension_rw, extension);
    assert_eq!(bookmark_data.target_flags, target_flags);
    assert_eq!(bookmark_data.folder_index, folder_index);
    assert_eq!(bookmark_data.uid, uid);
    assert_eq!(bookmark_data.username, username);
    assert_eq!(bookmark_data.creation_options, creation_options);
    assert_eq!(bookmark_data.is_executable, is_executable);
    assert_eq!(bookmark_data.security_extension_ro, extension);
    assert_eq!(bookmark_data.file_ref_flag, false);
}

#[test]
// Test a bookmark with RO Security Extension data
fn test_security_extension_ro() {
    let mut test_location = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_location.push("tests/test_data/systemevents.bookmark");
    let buffer = fs::read(test_location).unwrap();

    assert_eq!(buffer.len(), 892);

    let bookmark_data = macos_bookmarks::parser::parse_bookmark(&buffer).unwrap();
    assert_eq!(bookmark_data.creation, 599558400.0);
    assert_eq!(
        bookmark_data.path,
        ["System", "Library", "CoreServices", "System Events.app"]
    );
    assert_eq!(
        bookmark_data.cnid_path,
        [
            1152921500311879701,
            1152921500311993981,
            1152921500312123682,
            1152921500312197977
        ]
    );
    assert_eq!(bookmark_data.volume_path, "/");
    assert_eq!(bookmark_data.volume_url, "file:///");
    assert_eq!(bookmark_data.volume_name, "Macintosh HD");
    assert_eq!(
        bookmark_data.volume_uuid,
        "0A81F3B1-51D9-3335-B3E3-169C3640360D"
    );
    assert_eq!(bookmark_data.volume_creation, 599558400.0);
    assert_eq!(bookmark_data.volume_size, 85555372032);
    assert_eq!(bookmark_data.volume_flag, [4294967425, 4294972399, 0]);
    assert_eq!(bookmark_data.volume_root, true);
    assert_eq!(bookmark_data.localized_name, "System Events");
    assert_eq!(bookmark_data.security_extension_rw, String::new());
    assert_eq!(bookmark_data.target_flags, [530, 543, 538]);
    assert_eq!(bookmark_data.folder_index, 0);
    assert_eq!(bookmark_data.uid, 0);
    assert_eq!(bookmark_data.username, String::new());
    assert_eq!(bookmark_data.creation_options, 0);
    assert_eq!(bookmark_data.is_executable, true);
    assert_eq!(bookmark_data.file_ref_flag, false);
    assert_eq!(bookmark_data.security_extension_ro, "46d8327f9637aa681e789f0fc10ad53b5ab5343e2ccace15d15e508c16c64fbc;00;00000000;00000000;00000000;000000000000001a;com.apple.app-sandbox.read;01;0100000a;0fffffff0004db59;02;/system/library/coreservices/system events.app\0");
}

#[test]
// Parse a bookmark generated by the mac_alias Python package https://github.com/dmgbuild/mac_alias
fn test_mac_alias_bookmark() {
    let mut test_location = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_location.push("tests/test_data/macAlias.bookmark");
    let buffer = fs::read(test_location).unwrap();

    assert_eq!(buffer.len(), 884);
    let bookmark_data = macos_bookmarks::parser::parse_bookmark(&buffer).unwrap();
    assert_eq!(bookmark_data.creation, 677959217.851971);
    assert_eq!(
        bookmark_data.path,
        [
            "..",
            "..",
            "..",
            "Users",
            "puffycid",
            "Downloads",
            "powershell-7.2.5-osx-arm64.pkg"
        ]
    );
    assert_eq!(
        bookmark_data.cnid_path,
        [1152921500312725496, 1152921500311879701]
    );
    assert_eq!(bookmark_data.volume_path, "/System/Volumes/Data");
    assert_eq!(bookmark_data.volume_url, "file:///System/Volumes/Data");
    assert_eq!(bookmark_data.volume_name, "Macintosh HD - Data");
    assert_eq!(
        bookmark_data.volume_uuid,
        "96FB41C0-6CE9-4DA2-8435-35BC19C735A3"
    );
    assert_eq!(bookmark_data.volume_creation, 616544347.691502);
    assert_eq!(bookmark_data.volume_size, 2000662327296);
    assert_eq!(bookmark_data.volume_flag, [4294967425, 4294972399, 0]);
    assert_eq!(bookmark_data.volume_root, false);
    assert_eq!(bookmark_data.localized_name, String::new());
    assert_eq!(bookmark_data.security_extension_rw, String::new());
    assert_eq!(bookmark_data.target_flags, [1, 15, 0]);
    assert_eq!(bookmark_data.folder_index, 5);
    assert_eq!(bookmark_data.uid, 99);
    assert_eq!(bookmark_data.username, "unknown");
    assert_eq!(bookmark_data.creation_options, 512);
    assert_eq!(bookmark_data.is_executable, false);
    assert_eq!(bookmark_data.file_ref_flag, true);
    assert_eq!(bookmark_data.security_extension_ro, String::new());
}

#[test]
// Test a bookmark found in Safar Downloads PLIST
fn test_safari_downloads_bookmark_file() {
    let mut test_location = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_location.push("tests/test_data/downloads.bookmark");
    let buffer = fs::read(test_location).unwrap();

    assert_eq!(buffer.len(), 716);

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
    assert_eq!(bookmark.security_extension_rw, security_extension);
    assert_eq!(bookmark.security_extension_ro, security_extension);
    assert_eq!(bookmark.file_ref_flag, false);
}

#[test]
fn test_ventura_bookmark() {
    let mut test_location = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_location.push("tests/test_data/ventura.bookmark");
    let buffer = fs::read(test_location).unwrap();

    let results = macos_bookmarks::parser::parse_bookmark(&buffer).unwrap();
    assert_eq!(results.volume_size, 122107002880)
}

#[test]
#[should_panic(expected = "BadHeader")]
fn test_bad_sig() {
    let mut test_location = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_location.push("tests/test_data/bad_header.bookmark");
    let buffer = fs::read(test_location).unwrap();

    assert_eq!(buffer.len(), 756);

    let _ = macos_bookmarks::parser::parse_bookmark(&buffer).unwrap();
}

#[test]
#[should_panic(expected = "BadBookmarkData")]
fn test_bad_content() {
    let mut test_location = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_location.push("tests/test_data/bad_content.bookmark");
    let buffer = fs::read(test_location).unwrap();

    assert_eq!(buffer.len(), 377);

    let _ = macos_bookmarks::parser::parse_bookmark(&buffer).unwrap();
}
