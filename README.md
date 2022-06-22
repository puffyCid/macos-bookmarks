# macos-bookmarks

A simple macOS Bookmarks parser (and library) written in Rust!  
macOS Bookmarks are a form of shortcuts on a macOS system

# Use Case
There are several macOS applications and features that make sure of Bookmarks. Two interesting ones are:
+ macOS LoginItems. LoginItems are a form of persistence on a macOS system
+ Safari downloads. Downloaded files in Safari are tracked in a plist file called `Downloads.plist` this plist file actually contains Bookmark data

# Bookmark Data
Bookmarks contain a variety of intersting data such as:
1. Path to target binary
2. Target creation time
3. Volume UUID
4. Volume creation
5. Localized Name


# References
http://michaellynn.github.io/2015/10/24/apples-bookmarkdata-exposed/  
https://mac-alias.readthedocs.io/en/latest/bookmark_fmt.html
