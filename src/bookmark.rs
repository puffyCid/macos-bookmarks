use std::{
    fmt::Debug,
    mem::size_of,
    str::{from_utf8, Utf8Error},
};

use log::{debug, warn};
use nom::{
    bytes::complete::take,
    number::{
        complete::{be_f64, be_u32, le_i64, le_u16, le_u32, le_u64},
        streaming::le_i32,
    },
};
use serde::Serialize;

// Bookmark documentation:
// https://mac-alias.readthedocs.io/en/latest/bookmark_fmt.html
// http://michaellynn.github.io/2015/10/24/apples-bookmarkdata-exposed/
#[derive(Debug, Serialize)]
pub struct BookmarkData {
    pub path: Vec<String>,          // Path to binary to run
    pub cnid_path: Vec<i64>,        // Path represented as Catalog Node ID
    pub creation: f64,              // Created timestamp of binary target
    pub volume_path: String,        // Root
    pub volume_url: String,         // URL type
    pub volume_name: String,        // Name of Volume
    pub volume_uuid: String,        // Volume UUID string
    pub volume_size: i64,           // Size of Volume
    pub volume_creation: f64,       // Created timestamp of Volume
    pub volume_flag: Vec<u64>,      // Volume Property flags
    pub volume_root: bool,          // If Volume is filesystem root
    pub localized_name: String,     // Optional localized name of target binary
    pub security_extension: String, // Optional Security extension of target binary
    pub target_flags: Vec<u64>,     // Resource property flags
    pub username: String,           // Username related to bookmark
    pub folder_index: i64,          // Folder index number
    pub uid: i32,                   // User UID
    pub creation_options: i32,      // Bookmark creation options
}

#[derive(Debug)]
pub struct BookmarkHeader {
    pub signature: u32,            // Bookmark Signature "book"
    pub bookmark_data_length: u32, // Total size of bookmark
    pub version: u32,              // Possible version number
    pub bookmark_data_offset: u32, // Offset to start of bookmark data (always 0x30 (48)).
                                   // Followed by 32 bytes of empty/reserved space (48 bytes total)
}

#[derive(Debug)]
struct TableOfContentsOffset {
    table_of_contents_offset: u32, // Offset to start of Table of Contents (TOC)
}

#[derive(Debug)]
struct TableOfContentsHeader {
    data_length: u32, // Size of TOC
    record_type: u16, // Unused TOC record/key type (Possible magic number along side flags (0xfffffffe))
    flags: u16,       // Unused flag (Possible magic number along side record_type (0xfffffffe))
}

#[derive(Debug)]
struct TableOfContentsData {
    level: u32,              // TOC Data level or identifier (always 1?)
    next_record_offset: u32, // Offset to next TOC record
    number_of_records: u32,  // Number of records in TOC
}

#[derive(Debug)]
struct TableOfContentsDataRecord {
    record_type: u32, // Record/Key type
    data_offset: u32, // Offset to record data
    reserved: u32,    // Reserved (0)
}

#[derive(Debug)]
struct StandardDataRecord {
    data_length: u32,     // Length of data
    data_type: u32,       // Type of data
    record_data: Vec<u8>, // Data
    record_type: u32,     // Record type (from TableOfContentsDataRecord)
}

impl BookmarkData {
    // Data types
    const STRING_TYPE: u32 = 0x0101;
    const DATA_TYPE: u32 = 0x0201;
    const _NUMBER_ONE_BYTE: u32 = 0x0301;
    const _NUMBER_TWO_BYTE: u32 = 0x0302;
    const NUMBER_FOUR_BYTE: u32 = 0x0303;
    const NUMBER_EIGHT_BYTE: u32 = 0x0304;
    const _NUMBER_FLOAT: u32 = 0x0305;
    const _NUMBERBER_FLOAT64: u32 = 0x0306;
    const DATE: u32 = 0x0400;
    const _BOOL_FALSE: u32 = 0x0500;
    const BOOL_TRUE: u32 = 0x0501;
    const ARRAY_TYPE: u32 = 0x0601;
    const _DICTIONARY: u32 = 0x0701;
    const _UUID: u32 = 0x0801;
    const URL: u32 = 0x0901;
    const _URL_RELATIVE: u32 = 0x0902;

    // Table of Contents Key types
    const _UNKNOWN: u32 = 0x1003;
    const TARGET_PATH: u32 = 0x1004;
    const TARGET_CNID_PATH: u32 = 0x1005;
    const TARGET_FLAGS: u32 = 0x1010;
    const _TARGET_FILENAME: u32 = 0x1020;
    const TARGET_CREATION_DATE: u32 = 0x1040;
    const _UKNOWN2: u32 = 0x1054;
    const _UNKNOWN3: u32 = 0x1055;
    const _UNKNOWN4: u32 = 0x1056;
    const _UNKNOWN5: u32 = 0x1057;
    const _UNKNOWN6: u32 = 0x1101;
    const _UNKNOWN7: u32 = 0x1102;
    const _TOC_PATH: u32 = 0x2000;
    const VOLUME_PATH: u32 = 0x2002;
    const VOLUME_URL: u32 = 0x2005;
    const VOLUME_NAME: u32 = 0x2010;
    const VOLUME_UUID: u32 = 0x2011;
    const VOLUME_SIZE: u32 = 0x2012;
    const VOLUME_CREATION: u32 = 0x2013;
    const _VOLUME_BOOKMARK: u32 = 0x2040;
    const VOLUME_FLAGS: u32 = 0x2020;
    const VOLUME_ROOT: u32 = 0x2030;
    const _VOLUME_MOUNT_POINT: u32 = 0x2050;
    const _UNKNOWN8: u32 = 0x2070;
    const CONTAIN_FOLDER_INDEX: u32 = 0xc001;
    const CREATOR_USERNAME: u32 = 0xc011;
    const CREATOR_UID: u32 = 0xc012;
    const _FILE_REF_FLAG: u32 = 0xd001;
    const CREATION_OPTIONS: u32 = 0xd010;
    const _URL_LENGTH_ARRAY: u32 = 0xe003;
    const LOCALIZED_NAME: u32 = 0xf017;
    const _UNKNOWN9: u32 = 0xf022;
    const SECURITY_EXTENSION: u32 = 0xf080;
    const _UNKNOWN10: u32 = 0xf081;

    /// Parse bookmark header
    pub fn parse_bookmark_header(data: &[u8]) -> nom::IResult<&[u8], BookmarkHeader> {
        let mut bookmark_header = BookmarkHeader {
            signature: 0,
            bookmark_data_length: 0,
            version: 0,
            bookmark_data_offset: 0,
        };

        let (input, sig) = take(size_of::<u32>())(data)?;
        let (input, data_length) = take(size_of::<u32>())(input)?;
        let (input, version) = take(size_of::<u32>())(input)?;
        let (input, data_offset) = take(size_of::<u32>())(input)?;

        let filler_size: u32 = 32;
        let (input, _) = take(filler_size)(input)?;

        let (_, bookmark_sig) = le_u32(sig)?;
        let (_, bookmark_data_length) = le_u32(data_length)?;
        let (_, bookmark_version) = be_u32(version)?;
        let (_, bookmark_data_offset) = le_u32(data_offset)?;

        bookmark_header.signature = bookmark_sig;
        bookmark_header.bookmark_data_length = bookmark_data_length;
        bookmark_header.version = bookmark_version;
        bookmark_header.bookmark_data_offset = bookmark_data_offset;
        Ok((input, bookmark_header))
    }

    /// Parse the core bookmark data
    pub fn parse_bookmark_data(data: &[u8]) -> nom::IResult<&[u8], BookmarkData> {
        let mut book_data = TableOfContentsOffset {
            table_of_contents_offset: 0,
        };

        let (input, offset) = take(size_of::<u32>())(data)?;
        let (_, toc_offset) = le_u32(offset)?;

        book_data.table_of_contents_offset = toc_offset;
        let toc_offset_size: u32 = 4;
        let (input, core_data) = take(book_data.table_of_contents_offset - toc_offset_size)(input)?;

        let (input, toc_header) = BookmarkData::table_of_contents_header(input)?;

        let (toc_record_data, toc_content_data) =
            BookmarkData::table_of_contents_data(input, toc_header.data_length)?;

        let (_, toc_content_data_record) = BookmarkData::table_of_contents_record(
            toc_record_data,
            &toc_content_data.number_of_records,
        )?;

        let mut bookmark_data = BookmarkData {
            path: Vec::new(),
            cnid_path: Vec::new(),
            target_flags: Vec::new(),
            creation: 0.0,
            volume_path: String::new(),
            volume_url: String::new(),
            volume_name: String::new(),
            volume_uuid: String::new(),
            volume_size: 0,
            volume_creation: 0.0,
            volume_flag: Vec::new(),
            volume_root: false,
            localized_name: String::new(),
            security_extension: String::new(),
            username: String::new(),
            uid: 0,
            creation_options: 0,
            folder_index: 0,
        };

        for record in toc_content_data_record {
            let (_, standard_data) = BookmarkData::bookmark_standard_data(core_data, &record)?;
            let record_data = standard_data.record_data;
            let mut standard_data_vec: Vec<StandardDataRecord> = Vec::new();

            // If data type is ARRAY, standard_data data points to offsets that contain actual bookmark data
            if standard_data.data_type == BookmarkData::ARRAY_TYPE {
                let results_data = BookmarkData::bookmark_array(&record_data);
                match results_data {
                    Ok((_, results)) => {
                        if results.is_empty() {
                            continue;
                        }

                        let (_, std_data_vec) =
                            BookmarkData::bookmark_array_data(core_data, results, &record)?;

                        // Now we have data for actual bookmark data
                        standard_data_vec = std_data_vec;
                    }
                    Err(err) => warn!("Failed to get bookmark standard data: {:?}", err),
                }
            }

            // If we did not have to parse array data, get bookmark data based on record and data types
            if standard_data_vec.is_empty() {
                if standard_data.record_type == BookmarkData::TARGET_FLAGS
                    && standard_data.data_type == BookmarkData::DATA_TYPE
                {
                    let flag_data = BookmarkData::bookmark_target_flags(&record_data);
                    match flag_data {
                        Ok((_, flags)) => {
                            if flags.is_empty() {
                                continue;
                            }
                            bookmark_data.target_flags = flags;
                        }
                        Err(err) => warn!("Failed to parse Target Flags: {:?}", err),
                    }
                } else if standard_data.record_type == BookmarkData::TARGET_CREATION_DATE
                    && standard_data.data_type == BookmarkData::DATE
                {
                    let creation_data = BookmarkData::bookmark_data_type_date(&record_data);
                    match creation_data {
                        Ok((_, creation)) => bookmark_data.creation = creation,
                        Err(err) => warn!("Failed to parse Target creation timestamp: {:?}", err),
                    }
                } else if standard_data.record_type == BookmarkData::VOLUME_PATH
                    && standard_data.data_type == BookmarkData::STRING_TYPE
                {
                    let volume_root = BookmarkData::bookmark_data_type_string(&record_data);
                    match volume_root {
                        Ok(volume_root_data) => bookmark_data.volume_path = volume_root_data,
                        Err(err) => warn!("Failed to parse Volume Path: {:?}", err),
                    }
                } else if standard_data.record_type == BookmarkData::VOLUME_URL
                    && standard_data.data_type == BookmarkData::URL
                {
                    let volume_url_data = BookmarkData::bookmark_data_type_string(&record_data);
                    match volume_url_data {
                        Ok(volume_url) => bookmark_data.volume_url = volume_url,
                        Err(err) => warn!("Failed to parse Volume URL data: {:?}", err),
                    }
                } else if standard_data.record_type == BookmarkData::VOLUME_NAME
                    && standard_data.data_type == BookmarkData::STRING_TYPE
                {
                    let volume_name_data = BookmarkData::bookmark_data_type_string(&record_data);
                    match volume_name_data {
                        Ok(volume_name) => bookmark_data.volume_name = volume_name,
                        Err(err) => warn!("Failed to parse Volume Name data: {:?}", err),
                    }
                } else if standard_data.record_type == BookmarkData::VOLUME_UUID
                    && standard_data.data_type == BookmarkData::STRING_TYPE
                {
                    let volume_uuid_data = BookmarkData::bookmark_data_type_string(&record_data);
                    match volume_uuid_data {
                        Ok(volume_uuid) => bookmark_data.volume_uuid = volume_uuid,
                        Err(err) => warn!("Failed to parse Volume UUID: {:?}", err),
                    }
                } else if standard_data.record_type == BookmarkData::VOLUME_SIZE
                    && standard_data.data_type == BookmarkData::NUMBER_EIGHT_BYTE
                {
                    let test = BookmarkData::bookmark_data_type_number_eight(&record_data);
                    match test {
                        Ok((_, size)) => bookmark_data.volume_size = size,
                        Err(err) => warn!("Failed to parse Volume size: {:?}", err),
                    }
                } else if standard_data.record_type == BookmarkData::VOLUME_CREATION
                    && standard_data.data_type == BookmarkData::DATE
                {
                    let creation_data = BookmarkData::bookmark_data_type_date(&record_data);
                    match creation_data {
                        Ok((_, creation)) => bookmark_data.volume_creation = creation,
                        Err(err) => warn!("Failed to parse Volume Creation timestamp: {:?}", err),
                    }
                } else if standard_data.record_type == BookmarkData::VOLUME_FLAGS
                    && standard_data.data_type == BookmarkData::DATA_TYPE
                {
                    let flags_data = BookmarkData::bookmark_target_flags(&record_data);
                    match flags_data {
                        Ok((_, flags)) => bookmark_data.volume_flag = flags,
                        Err(err) => warn!("Failed to parse Volume Flags: {:?}", err),
                    }
                } else if standard_data.record_type == BookmarkData::VOLUME_ROOT
                    && standard_data.data_type == BookmarkData::BOOL_TRUE
                {
                    bookmark_data.volume_root = true;
                } else if standard_data.record_type == BookmarkData::LOCALIZED_NAME
                    && standard_data.data_type == BookmarkData::STRING_TYPE
                {
                    let local_name_data = BookmarkData::bookmark_data_type_string(&record_data);
                    match local_name_data {
                        Ok(local_name) => bookmark_data.localized_name = local_name,
                        Err(err) => warn!("Failed to parse Localized Name: {:?}", err),
                    }
                } else if standard_data.record_type == BookmarkData::SECURITY_EXTENSION
                    && standard_data.data_type == BookmarkData::DATA_TYPE
                {
                    let extension_data = BookmarkData::bookmark_data_type_string(&record_data);
                    match extension_data {
                        Ok(extension) => bookmark_data.security_extension = extension,
                        Err(err) => warn!("Failed to parse Security Extension: {:?}", err),
                    }
                } else if standard_data.record_type == BookmarkData::CREATOR_USERNAME
                    && standard_data.data_type == BookmarkData::STRING_TYPE
                {
                    let username_data = BookmarkData::bookmark_data_type_string(&record_data);
                    match username_data {
                        Ok(username) => bookmark_data.username = username,
                        Err(err) => warn!("Failed to parse bookmark username: {:?}", err),
                    }
                } else if standard_data.record_type == BookmarkData::CONTAIN_FOLDER_INDEX
                    && standard_data.data_type == BookmarkData::NUMBER_FOUR_BYTE
                {
                    let index_data = BookmarkData::bookmark_data_type_number_four(&record_data);
                    match index_data {
                        Ok((_, index)) => bookmark_data.folder_index = index as i64,
                        Err(err) => warn!("Failed to parse bookmark folder index: {:?}", err),
                    }
                } else if standard_data.record_type == BookmarkData::CONTAIN_FOLDER_INDEX
                    && standard_data.data_type == BookmarkData::NUMBER_EIGHT_BYTE
                {
                    let index_data = BookmarkData::bookmark_data_type_number_eight(&record_data);
                    match index_data {
                        Ok((_, index)) => bookmark_data.folder_index = index,
                        Err(err) => warn!("Failed to parse bookmark folder index: {:?}", err),
                    }
                } else if standard_data.record_type == BookmarkData::CREATOR_UID
                    && standard_data.data_type == BookmarkData::NUMBER_FOUR_BYTE
                {
                    let uid_data = BookmarkData::bookmark_data_type_number_four(&record_data);
                    match uid_data {
                        Ok((_, uid)) => bookmark_data.uid = uid,
                        Err(err) => warn!("Failed to parse bookmark Creator UID: {:?}", err),
                    }
                } else if standard_data.record_type == BookmarkData::CREATION_OPTIONS
                    && standard_data.data_type == BookmarkData::NUMBER_FOUR_BYTE
                {
                    let creation_options_data =
                        BookmarkData::bookmark_data_type_number_four(&record_data);
                    match creation_options_data {
                        Ok((_, options)) => bookmark_data.creation_options = options,
                        Err(err) => warn!("Failed to parse bookmark Creation options: {:?}", err),
                    }
                } else {
                    warn!(
                        "Unknown Record Type: {} and Data type: {}",
                        standard_data.record_type, standard_data.data_type
                    );
                    debug!("Record data: {:?}", record_data);
                }
                continue;
            }

            // Get bookmark array data based on data and record types
            for standard_data in standard_data_vec {
                if standard_data.data_type == BookmarkData::STRING_TYPE
                    && standard_data.record_type == BookmarkData::TARGET_PATH
                {
                    let path_data =
                        BookmarkData::bookmark_data_type_string(&standard_data.record_data);
                    match path_data {
                        Ok(path) => bookmark_data.path.push(path),
                        Err(_err) => continue,
                    }
                } else if standard_data.data_type == BookmarkData::NUMBER_EIGHT_BYTE
                    && standard_data.record_type == BookmarkData::TARGET_CNID_PATH
                {
                    let cnid_data = BookmarkData::bookmark_cnid(&standard_data.record_data);
                    match cnid_data {
                        Ok((_, cnid)) => bookmark_data.cnid_path.push(cnid),
                        Err(_err) => continue,
                    }
                }
            }
        }
        Ok((input, bookmark_data))
    }

    /// Parse the bookmark array data
    fn bookmark_array_data<'a>(
        data: &'a [u8],
        array_offsets: Vec<u32>,
        record: &TableOfContentsDataRecord,
    ) -> nom::IResult<&'a [u8], Vec<StandardDataRecord>> {
        let mut standard_data_vec: Vec<StandardDataRecord> = Vec::new();

        for offset in array_offsets {
            let data_record = TableOfContentsDataRecord {
                record_type: record.record_type,
                data_offset: offset,
                reserved: 0,
            };
            let (_, results) = BookmarkData::bookmark_standard_data(data, &data_record)?;
            standard_data_vec.push(results);
        }

        Ok((data, standard_data_vec))
    }

    /// Parse the Table of Contents (TOC) header
    fn table_of_contents_header(data: &[u8]) -> nom::IResult<&[u8], TableOfContentsHeader> {
        let mut toc_header = TableOfContentsHeader {
            data_length: 0,
            record_type: 0,
            flags: 0,
        };

        let (input, length) = take(size_of::<u32>())(data)?;
        let (input, record_type) = take(size_of::<u16>())(input)?;
        let (input, flags) = take(size_of::<u16>())(input)?;

        let (_, toc_length) = le_u32(length)?;
        let (_, toc_record_type) = le_u16(record_type)?;
        let (_, toc_flags) = le_u16(flags)?;

        toc_header.data_length = toc_length;
        toc_header.record_type = toc_record_type;
        toc_header.flags = toc_flags;

        Ok((input, toc_header))
    }

    /// Parse the TOC data
    fn table_of_contents_data(
        data: &[u8],
        data_length: u32,
    ) -> nom::IResult<&[u8], TableOfContentsData> {
        let mut toc_data = TableOfContentsData {
            level: 0,
            next_record_offset: 0,
            number_of_records: 0,
        };

        let (input, level) = take(size_of::<u32>())(data)?;
        let (input, next_record_offset) = take(size_of::<u32>())(input)?;
        let (input, number_of_records) = take(size_of::<u32>())(input)?;

        let mut final_input = input;

        let (_, toc_level) = le_u32(level)?;
        let (_, toc_next_record) = le_u32(next_record_offset)?;
        let (_, toc_number_records) = le_u32(number_of_records)?;

        toc_data.level = toc_level;
        toc_data.next_record_offset = toc_next_record;
        toc_data.number_of_records = toc_number_records;

        let record_size = 12;
        let record_data = record_size * toc_data.number_of_records;

        // Verify TOC data length is equal to number of records (Number of Records * Record Size (12 bytes))
        // Some TOC headers may give incorrect? data length (they are 8 bytes short, https://mac-alias.readthedocs.io/en/latest/bookmark_fmt.html)
        if record_data > data_length {
            let (_, actual_record_data) = take(record_data)(input)?;
            final_input = actual_record_data;
        }
        Ok((final_input, toc_data))
    }

    /// Parse the TOC data record
    fn table_of_contents_record<'a>(
        data: &'a [u8],
        records: &u32,
    ) -> nom::IResult<&'a [u8], Vec<TableOfContentsDataRecord>> {
        let mut input_data = data;
        let mut record: u32 = 0;
        let mut toc_records_vec: Vec<TableOfContentsDataRecord> = Vec::new();

        // Loop through until all records have been parsed
        loop {
            if &record == records {
                break;
            }
            record += 1;
            let mut toc_data_record = TableOfContentsDataRecord {
                record_type: 0,
                data_offset: 0,
                reserved: 0,
            };

            let (input, record_type) = take(size_of::<u32>())(input_data)?;
            let (input, offset) = take(size_of::<u32>())(input)?;
            let (input, reserved) = take(size_of::<u32>())(input)?;
            input_data = input;

            let (_, toc_record) = le_u32(record_type)?;
            let (_, toc_offset) = le_u32(offset)?;
            let (_, toc_reserved) = le_u32(reserved)?;

            toc_data_record.record_type = toc_record;
            toc_data_record.data_offset = toc_offset;
            toc_data_record.reserved = toc_reserved;
            toc_records_vec.push(toc_data_record);
        }
        Ok((input_data, toc_records_vec))
    }

    /// Parse the bookmark standard data
    fn bookmark_standard_data<'a>(
        bookmark_data: &'a [u8],
        toc_record: &TableOfContentsDataRecord,
    ) -> nom::IResult<&'a [u8], StandardDataRecord> {
        let mut toc_standard_data = StandardDataRecord {
            data_length: 0,
            record_data: Vec::new(),
            data_type: 0,
            record_type: 0,
        };
        let toc_offset_value: u32 = 4;

        // Subtract toc offset value from data offset since we already nom'd the value
        let offset = (toc_record.data_offset - toc_offset_value) as usize;

        // Nom data til standard data info
        let (input, _) = take(offset)(bookmark_data)?;

        let (input, length) = take(size_of::<u32>())(input)?;
        let (input, data_type) = take(size_of::<u32>())(input)?;

        let (_, standard_length) = le_u32(length)?;
        let (_, standard_data_type) = le_u32(data_type)?;

        let (input, record_data) = take(standard_length)(input)?;

        toc_standard_data.data_length = standard_length;
        toc_standard_data.data_type = standard_data_type;
        toc_standard_data.record_data = record_data.to_vec();
        toc_standard_data.record_type = toc_record.record_type;

        Ok((input, toc_standard_data))
    }

    /// Get the offsets for the array data
    fn bookmark_array(standard_data: &[u8]) -> nom::IResult<&[u8], Vec<u32>> {
        let mut array_offsets: Vec<u32> = Vec::new();
        let mut input = standard_data;
        let offset_size: u32 = 4;

        loop {
            let (input_data, offset) = take(offset_size)(input)?;
            let (_, data_offsets) = le_u32(offset)?;

            array_offsets.push(data_offsets);
            input = input_data;
            if input_data.is_empty() {
                break;
            }
        }
        Ok((input, array_offsets))
    }

    /// Get the path/strings related to bookmark
    fn bookmark_data_type_string(standard_data: &[u8]) -> Result<String, Utf8Error> {
        let path = from_utf8(standard_data)?;
        Ok(path.to_string())
    }

    /// Get the CNID path for the target
    fn bookmark_cnid(standard_data: &[u8]) -> nom::IResult<&[u8], i64> {
        let (data, cnid) = le_i64(standard_data)?;
        Ok((data, cnid))
    }

    /// Get bookmark target flags
    fn bookmark_target_flags(standard_data: &[u8]) -> nom::IResult<&[u8], Vec<u64>> {
        let mut input = standard_data;
        let mut array_flags: Vec<u64> = Vec::new();
        let max_flag_size = 3;

        // Target flags are composed of three (3) 8 byte values
        loop {
            let (data, flag) = take(size_of::<u64>())(input)?;
            input = data;
            let (_, flags) = le_u64(flag)?;
            array_flags.push(flags);
            if input.is_empty() || array_flags.len() == max_flag_size {
                break;
            }
        }
        Ok((input, array_flags))
    }

    /// Get bookmark volume size
    fn bookmark_data_type_number_eight(standard_data: &[u8]) -> nom::IResult<&[u8], i64> {
        let (data, size) = le_i64(standard_data)?;
        Ok((data, size))
    }

    /// Get bookmark folder index
    fn bookmark_data_type_number_four(standard_data: &[u8]) -> nom::IResult<&[u8], i32> {
        let (data, index) = le_i32(standard_data)?;
        Ok((data, index))
    }

    /// Get bookmark creation timestamps
    fn bookmark_data_type_date(standard_data: &[u8]) -> nom::IResult<&[u8], f64> {
        //Apple stores timestamps as Big Endian Float64
        let (data, creation) = be_f64(standard_data)?;
        Ok((data, creation))
    }
}

#[cfg(test)]
mod tests {

    use super::{BookmarkData, TableOfContentsDataRecord};
    #[test]
    fn test_bookmark_header() {
        let test_header = [
            98, 111, 111, 107, 72, 2, 0, 0, 0, 0, 4, 16, 48, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let (_, header) = BookmarkData::parse_bookmark_header(&test_header).unwrap();
        let book_sig: u32 = 1802465122;
        let book_length: u32 = 584;
        let book_offset: u32 = 48;
        let book_version: u32 = 1040;
        assert_eq!(header.signature, book_sig);
        assert_eq!(header.bookmark_data_length, book_length);
        assert_eq!(header.bookmark_data_offset, book_offset);
        assert_eq!(header.version, book_version);
    }

    #[test]
    fn test_table_of_contents_header() {
        let test_header = [192, 0, 0, 0, 254, 255, 255, 255];
        let (_, header) = BookmarkData::table_of_contents_header(&test_header).unwrap();
        let toc_length: u32 = 192;
        let toc_record_type: u16 = 65534;
        let toc_flags: u16 = 65535;
        assert_eq!(header.data_length, toc_length);
        assert_eq!(header.record_type, toc_record_type);
        assert_eq!(header.flags, toc_flags);
    }

    #[test]
    fn test_bookmark() {
        let test_data = [
            8, 2, 0, 0, 12, 0, 0, 0, 1, 1, 0, 0, 65, 112, 112, 108, 105, 99, 97, 116, 105, 111,
            110, 115, 13, 0, 0, 0, 1, 1, 0, 0, 83, 121, 110, 99, 116, 104, 105, 110, 103, 46, 97,
            112, 112, 0, 0, 0, 8, 0, 0, 0, 1, 6, 0, 0, 4, 0, 0, 0, 24, 0, 0, 0, 8, 0, 0, 0, 4, 3,
            0, 0, 103, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 4, 3, 0, 0, 42, 198, 10, 0, 0, 0, 0, 0, 8,
            0, 0, 0, 1, 6, 0, 0, 64, 0, 0, 0, 80, 0, 0, 0, 8, 0, 0, 0, 0, 4, 0, 0, 65, 195, 213,
            41, 226, 128, 0, 0, 24, 0, 0, 0, 1, 2, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 15, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 1, 9, 0, 0, 102, 105, 108, 101, 58, 47, 47,
            47, 12, 0, 0, 0, 1, 1, 0, 0, 77, 97, 99, 105, 110, 116, 111, 115, 104, 32, 72, 68, 8,
            0, 0, 0, 4, 3, 0, 0, 0, 96, 127, 115, 37, 0, 0, 0, 8, 0, 0, 0, 0, 4, 0, 0, 65, 172,
            190, 215, 104, 0, 0, 0, 36, 0, 0, 0, 1, 1, 0, 0, 48, 65, 56, 49, 70, 51, 66, 49, 45,
            53, 49, 68, 57, 45, 51, 51, 51, 53, 45, 66, 51, 69, 51, 45, 49, 54, 57, 67, 51, 54, 52,
            48, 51, 54, 48, 68, 24, 0, 0, 0, 1, 2, 0, 0, 129, 0, 0, 0, 1, 0, 0, 0, 239, 19, 0, 0,
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 47, 0, 0, 0, 0, 0, 0, 0, 1,
            5, 0, 0, 9, 0, 0, 0, 1, 1, 0, 0, 83, 121, 110, 99, 116, 104, 105, 110, 103, 0, 0, 0,
            166, 0, 0, 0, 1, 2, 0, 0, 54, 52, 99, 98, 55, 101, 97, 97, 57, 97, 49, 98, 98, 99, 99,
            99, 52, 101, 49, 51, 57, 55, 99, 57, 102, 50, 97, 52, 49, 49, 101, 98, 101, 53, 51, 57,
            99, 100, 50, 57, 59, 48, 48, 48, 48, 48, 48, 48, 48, 59, 48, 48, 48, 48, 48, 48, 48,
            48, 59, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 50, 48, 59, 99, 111,
            109, 46, 97, 112, 112, 108, 101, 46, 97, 112, 112, 45, 115, 97, 110, 100, 98, 111, 120,
            46, 114, 101, 97, 100, 45, 119, 114, 105, 116, 101, 59, 48, 49, 59, 48, 49, 48, 48, 48,
            48, 48, 52, 59, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 97, 99, 54, 50, 97, 59, 47,
            97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 115, 47, 115, 121, 110, 99, 116,
            104, 105, 110, 103, 46, 97, 112, 112, 0, 0, 0, 180, 0, 0, 0, 254, 255, 255, 255, 1, 0,
            0, 0, 0, 0, 0, 0, 14, 0, 0, 0, 4, 16, 0, 0, 48, 0, 0, 0, 0, 0, 0, 0, 5, 16, 0, 0, 96,
            0, 0, 0, 0, 0, 0, 0, 16, 16, 0, 0, 128, 0, 0, 0, 0, 0, 0, 0, 64, 16, 0, 0, 112, 0, 0,
            0, 0, 0, 0, 0, 2, 32, 0, 0, 48, 1, 0, 0, 0, 0, 0, 0, 5, 32, 0, 0, 160, 0, 0, 0, 0, 0,
            0, 0, 16, 32, 0, 0, 176, 0, 0, 0, 0, 0, 0, 0, 17, 32, 0, 0, 228, 0, 0, 0, 0, 0, 0, 0,
            18, 32, 0, 0, 196, 0, 0, 0, 0, 0, 0, 0, 19, 32, 0, 0, 212, 0, 0, 0, 0, 0, 0, 0, 32, 32,
            0, 0, 16, 1, 0, 0, 0, 0, 0, 0, 48, 32, 0, 0, 60, 1, 0, 0, 0, 0, 0, 0, 23, 240, 0, 0,
            68, 1, 0, 0, 0, 0, 0, 0, 128, 240, 0, 0, 88, 1, 0, 0, 0, 0, 0, 0,
        ];
        let (_, bookmark) = BookmarkData::parse_bookmark_data(&test_data).unwrap();
        let app_path_len = 2;
        let cnid_path_len = 2;
        let target_creation = 665473989.0;
        let volume_creation = 241134516.0;
        let target_flags_len = 3;

        assert_eq!(bookmark.path.len(), app_path_len);
        assert_eq!(bookmark.cnid_path.len(), cnid_path_len);
        assert_eq!(bookmark.creation, target_creation);
        assert_eq!(bookmark.volume_creation, volume_creation);
        assert_eq!(bookmark.target_flags.len(), target_flags_len);
    }

    #[test]
    fn test_table_of_contents_data() {
        let test_data = [
            1, 0, 0, 0, 0, 0, 0, 0, 15, 0, 0, 0, 4, 16, 0, 0, 52, 0, 0, 0, 0, 0, 0, 0, 5, 16, 0, 0,
        ];
        let record_data_size = 192;
        let (_, toc_data) =
            BookmarkData::table_of_contents_data(&test_data, record_data_size).unwrap();
        let level = 1;
        let next_record_offset = 0;
        let number_of_records = 15;
        assert_eq!(toc_data.level, level);
        assert_eq!(toc_data.next_record_offset, next_record_offset);
        assert_eq!(toc_data.number_of_records, number_of_records);
    }

    #[test]
    fn test_table_of_contents_record() {
        let test_record = [
            4, 16, 0, 0, 48, 0, 0, 0, 0, 0, 0, 0, 5, 16, 0, 0, 96, 0, 0, 0, 0, 0, 0, 0, 16, 16, 0,
            0, 128, 0, 0, 0, 0, 0, 0, 0, 64, 16, 0, 0, 112, 0, 0, 0, 0, 0, 0, 0, 2, 32, 0, 0, 48,
            1, 0, 0, 0, 0, 0, 0, 5, 32, 0, 0, 160, 0, 0, 0, 0, 0, 0, 0, 16, 32, 0, 0, 176, 0, 0, 0,
            0, 0, 0, 0, 17, 32, 0, 0, 228, 0, 0, 0, 0, 0, 0, 0, 18, 32, 0, 0, 196, 0, 0, 0, 0, 0,
            0, 0, 19, 32, 0, 0, 212, 0, 0, 0, 0, 0, 0, 0, 32, 32, 0, 0, 16, 1, 0, 0, 0, 0, 0, 0,
            48, 32, 0, 0, 60, 1, 0, 0, 0, 0, 0, 0, 23, 240, 0, 0, 68, 1, 0, 0, 0, 0, 0, 0, 128,
            240, 0, 0, 88, 1, 0, 0, 0, 0, 0, 0,
        ];
        let records = 14;

        let (_, record) = BookmarkData::table_of_contents_record(&test_record, &records).unwrap();
        let record_type = 4100;
        let record_offset = 48;
        let record_reserved = 0;

        assert_eq!(record[0].record_type, record_type);
        assert_eq!(record[0].data_offset, record_offset);
        assert_eq!(record[0].reserved, record_reserved);
        assert_eq!(record.len(), records as usize);
    }

    #[test]
    fn test_bookmark_standard_data() {
        let bookmark_data = [
            12, 0, 0, 0, 1, 1, 0, 0, 65, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 115, 13,
            0, 0, 0, 1, 1, 0, 0, 83, 121, 110, 99, 116, 104, 105, 110, 103, 46, 97, 112, 112, 0, 0,
            0, 8, 0, 0, 0, 1, 6, 0, 0, 4, 0, 0, 0, 24, 0, 0, 0, 8, 0, 0, 0, 4, 3, 0, 0, 103, 0, 0,
            0, 0, 0, 0, 0, 8, 0, 0, 0, 4, 3, 0, 0, 42, 198, 10, 0, 0, 0, 0, 0, 8, 0, 0, 0, 1, 6, 0,
            0, 64, 0, 0, 0, 80, 0, 0, 0, 8, 0, 0, 0, 0, 4, 0, 0, 65, 195, 213, 41, 226, 128, 0, 0,
            24, 0, 0, 0, 1, 2, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 8, 0, 0, 0, 1, 9, 0, 0, 102, 105, 108, 101, 58, 47, 47, 47, 12, 0, 0, 0, 1,
            1, 0, 0, 77, 97, 99, 105, 110, 116, 111, 115, 104, 32, 72, 68, 8, 0, 0, 0, 4, 3, 0, 0,
            0, 96, 127, 115, 37, 0, 0, 0, 8, 0, 0, 0, 0, 4, 0, 0, 65, 172, 190, 215, 104, 0, 0, 0,
            36, 0, 0, 0, 1, 1, 0, 0, 48, 65, 56, 49, 70, 51, 66, 49, 45, 53, 49, 68, 57, 45, 51,
            51, 51, 53, 45, 66, 51, 69, 51, 45, 49, 54, 57, 67, 51, 54, 52, 48, 51, 54, 48, 68, 24,
            0, 0, 0, 1, 2, 0, 0, 129, 0, 0, 0, 1, 0, 0, 0, 239, 19, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 47, 0, 0, 0, 0, 0, 0, 0, 1, 5, 0, 0, 9, 0, 0, 0, 1,
            1, 0, 0, 83, 121, 110, 99, 116, 104, 105, 110, 103, 0, 0, 0, 166, 0, 0, 0, 1, 2, 0, 0,
            54, 52, 99, 98, 55, 101, 97, 97, 57, 97, 49, 98, 98, 99, 99, 99, 52, 101, 49, 51, 57,
            55, 99, 57, 102, 50, 97, 52, 49, 49, 101, 98, 101, 53, 51, 57, 99, 100, 50, 57, 59, 48,
            48, 48, 48, 48, 48, 48, 48, 59, 48, 48, 48, 48, 48, 48, 48, 48, 59, 48, 48, 48, 48, 48,
            48, 48, 48, 48, 48, 48, 48, 48, 48, 50, 48, 59, 99, 111, 109, 46, 97, 112, 112, 108,
            101, 46, 97, 112, 112, 45, 115, 97, 110, 100, 98, 111, 120, 46, 114, 101, 97, 100, 45,
            119, 114, 105, 116, 101, 59, 48, 49, 59, 48, 49, 48, 48, 48, 48, 48, 52, 59, 48, 48,
            48, 48, 48, 48, 48, 48, 48, 48, 48, 97, 99, 54, 50, 97, 59, 47, 97, 112, 112, 108, 105,
            99, 97, 116, 105, 111, 110, 115, 47, 115, 121, 110, 99, 116, 104, 105, 110, 103, 46,
            97, 112, 112, 0, 0, 0,
        ];
        let toc_record = TableOfContentsDataRecord {
            record_type: 8209,
            data_offset: 228,
            reserved: 0,
        };
        let (_, std_data) =
            BookmarkData::bookmark_standard_data(&bookmark_data, &toc_record).unwrap();

        let data_length = 36;
        let data_type = 257;
        let record_data = [
            48, 65, 56, 49, 70, 51, 66, 49, 45, 53, 49, 68, 57, 45, 51, 51, 51, 53, 45, 66, 51, 69,
            51, 45, 49, 54, 57, 67, 51, 54, 52, 48, 51, 54, 48, 68,
        ];
        let record_type = 8209;

        assert_eq!(std_data.data_length, data_length);
        assert_eq!(std_data.data_type, data_type);
        assert_eq!(std_data.record_data, record_data);
        assert_eq!(std_data.record_type, record_type);
    }

    #[test]
    fn test_bookmark_array_data() {
        let test_data = [
            12, 0, 0, 0, 1, 1, 0, 0, 65, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 115, 13,
            0, 0, 0, 1, 1, 0, 0, 83, 121, 110, 99, 116, 104, 105, 110, 103, 46, 97, 112, 112, 0, 0,
            0, 8, 0, 0, 0, 1, 6, 0, 0, 4, 0, 0, 0, 24, 0, 0, 0, 8, 0, 0, 0, 4, 3, 0, 0, 103, 0, 0,
            0, 0, 0, 0, 0, 8, 0, 0, 0, 4, 3, 0, 0, 42, 198, 10, 0, 0, 0, 0, 0, 8, 0, 0, 0, 1, 6, 0,
            0, 64, 0, 0, 0, 80, 0, 0, 0, 8, 0, 0, 0, 0, 4, 0, 0, 65, 195, 213, 41, 226, 128, 0, 0,
            24, 0, 0, 0, 1, 2, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 8, 0, 0, 0, 1, 9, 0, 0, 102, 105, 108, 101, 58, 47, 47, 47, 12, 0, 0, 0, 1,
            1, 0, 0, 77, 97, 99, 105, 110, 116, 111, 115, 104, 32, 72, 68, 8, 0, 0, 0, 4, 3, 0, 0,
            0, 96, 127, 115, 37, 0, 0, 0, 8, 0, 0, 0, 0, 4, 0, 0, 65, 172, 190, 215, 104, 0, 0, 0,
            36, 0, 0, 0, 1, 1, 0, 0, 48, 65, 56, 49, 70, 51, 66, 49, 45, 53, 49, 68, 57, 45, 51,
            51, 51, 53, 45, 66, 51, 69, 51, 45, 49, 54, 57, 67, 51, 54, 52, 48, 51, 54, 48, 68, 24,
            0, 0, 0, 1, 2, 0, 0, 129, 0, 0, 0, 1, 0, 0, 0, 239, 19, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 47, 0, 0, 0, 0, 0, 0, 0, 1, 5, 0, 0, 9, 0, 0, 0, 1,
            1, 0, 0, 83, 121, 110, 99, 116, 104, 105, 110, 103, 0, 0, 0, 166, 0, 0, 0, 1, 2, 0, 0,
            54, 52, 99, 98, 55, 101, 97, 97, 57, 97, 49, 98, 98, 99, 99, 99, 52, 101, 49, 51, 57,
            55, 99, 57, 102, 50, 97, 52, 49, 49, 101, 98, 101, 53, 51, 57, 99, 100, 50, 57, 59, 48,
            48, 48, 48, 48, 48, 48, 48, 59, 48, 48, 48, 48, 48, 48, 48, 48, 59, 48, 48, 48, 48, 48,
            48, 48, 48, 48, 48, 48, 48, 48, 48, 50, 48, 59, 99, 111, 109, 46, 97, 112, 112, 108,
            101, 46, 97, 112, 112, 45, 115, 97, 110, 100, 98, 111, 120, 46, 114, 101, 97, 100, 45,
            119, 114, 105, 116, 101, 59, 48, 49, 59, 48, 49, 48, 48, 48, 48, 48, 52, 59, 48, 48,
            48, 48, 48, 48, 48, 48, 48, 48, 48, 97, 99, 54, 50, 97, 59, 47, 97, 112, 112, 108, 105,
            99, 97, 116, 105, 111, 110, 115, 47, 115, 121, 110, 99, 116, 104, 105, 110, 103, 46,
            97, 112, 112, 0, 0, 0,
        ];
        let test_array_offsets = [4, 24];
        let toc_record = TableOfContentsDataRecord {
            record_type: 4100,
            data_offset: 48,
            reserved: 0,
        };
        let records = 2;

        let (_, std_record) = BookmarkData::bookmark_array_data(
            &test_data,
            (&test_array_offsets).to_vec(),
            &toc_record,
        )
        .unwrap();
        let record_type = 4100;
        let data_type = 257;
        let record_data = [65, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 115];
        let data_length = 12;

        assert_eq!(std_record[0].record_type, record_type);
        assert_eq!(std_record[0].data_type, data_type);
        assert_eq!(std_record[0].record_data, record_data);
        assert_eq!(std_record[0].data_length, data_length);

        assert_eq!(std_record.len(), records);
    }

    #[test]
    fn test_bookmark_array() {
        let test_array = [4, 0, 0, 0, 24, 0, 0, 0];

        let (_, book_array) = BookmarkData::bookmark_array(&test_array).unwrap();
        let offset = 4;
        let offset_2 = 24;

        let offsets = 2;
        assert_eq!(book_array.len(), offsets);

        assert_eq!(book_array[0], offset);
        assert_eq!(book_array[1], offset_2);
    }

    #[test]
    fn test_bookmark_data_type_string() {
        let test_path = [83, 121, 110, 99, 116, 104, 105, 110, 103];

        let book_path = BookmarkData::bookmark_data_type_string(&test_path).unwrap();
        let path = "Syncthing";
        assert_eq!(book_path, path);
    }

    #[test]
    fn test_bookmark_cnid() {
        let test_cnid = [42, 198, 10, 0, 0, 0, 0, 0];

        let (_, book_cnid) = BookmarkData::bookmark_cnid(&test_cnid).unwrap();
        let cnid = 706090;
        assert_eq!(book_cnid, cnid);
    }

    #[test]
    fn test_bookmark_target_flags() {
        let test_flags = [
            129, 0, 0, 0, 1, 0, 0, 0, 239, 19, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];

        let (_, book_flags) = BookmarkData::bookmark_target_flags(&test_flags).unwrap();
        let flag = 4294967425;
        let flag_2 = 4294972399;
        let flag_3 = 0;

        let flags = 3;

        assert_eq!(book_flags.len(), flags);
        assert_eq!(book_flags[0], flag);
        assert_eq!(book_flags[1], flag_2);
        assert_eq!(book_flags[2], flag_3);
    }

    #[test]
    fn test_bookmark_data_type_number_eight() {
        let test_volume_size = [0, 96, 127, 115, 37, 0, 0, 0];

        let (_, book_size) =
            BookmarkData::bookmark_data_type_number_eight(&test_volume_size).unwrap();
        let size = 160851517440;

        assert_eq!(book_size, size);
    }

    #[test]
    fn test_bookmark_data_type_date() {
        let test_creation = [65, 172, 190, 215, 104, 0, 0, 0];

        let (_, book_creation) = BookmarkData::bookmark_data_type_date(&test_creation).unwrap();
        let creation = 241134516.0;

        assert_eq!(book_creation, creation);
    }

    #[test]
    fn test_bookmark_data_type_number_four() {
        let test_creation = [0, 0, 0, 32];

        let (_, creation_options) =
            BookmarkData::bookmark_data_type_number_four(&test_creation).unwrap();
        let options = 536870912;
        assert_eq!(creation_options, options);
    }

    #[test]
    fn test_safari_downloads_bookmark() {
        let data = [
            98, 111, 111, 107, 204, 2, 0, 0, 0, 0, 4, 16, 48, 0, 0, 0, 217, 10, 110, 155, 143, 43,
            6, 0, 139, 200, 168, 230, 42, 214, 22, 102, 103, 228, 112, 159, 141, 163, 20, 27, 36,
            83, 233, 178, 57, 208, 89, 105, 200, 1, 0, 0, 4, 0, 0, 0, 3, 3, 0, 0, 0, 24, 0, 40, 5,
            0, 0, 0, 1, 1, 0, 0, 85, 115, 101, 114, 115, 0, 0, 0, 8, 0, 0, 0, 1, 1, 0, 0, 112, 117,
            102, 102, 121, 99, 105, 100, 9, 0, 0, 0, 1, 1, 0, 0, 68, 111, 119, 110, 108, 111, 97,
            100, 115, 0, 0, 0, 28, 0, 0, 0, 1, 1, 0, 0, 112, 111, 119, 101, 114, 115, 104, 101,
            108, 108, 45, 55, 46, 50, 46, 52, 45, 111, 115, 120, 45, 120, 54, 52, 46, 112, 107,
            103, 16, 0, 0, 0, 1, 6, 0, 0, 16, 0, 0, 0, 32, 0, 0, 0, 48, 0, 0, 0, 68, 0, 0, 0, 8, 0,
            0, 0, 4, 3, 0, 0, 79, 83, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 4, 3, 0, 0, 11, 128, 5, 0, 0,
            0, 0, 0, 8, 0, 0, 0, 4, 3, 0, 0, 62, 128, 5, 0, 0, 0, 0, 0, 8, 0, 0, 0, 4, 3, 0, 0,
            216, 194, 61, 2, 0, 0, 0, 0, 16, 0, 0, 0, 1, 6, 0, 0, 128, 0, 0, 0, 144, 0, 0, 0, 160,
            0, 0, 0, 176, 0, 0, 0, 8, 0, 0, 0, 0, 4, 0, 0, 65, 196, 48, 15, 162, 9, 145, 58, 24, 0,
            0, 0, 1, 2, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 8, 0, 0, 0, 4, 3, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 3, 3, 0, 0, 245, 1, 0,
            0, 8, 0, 0, 0, 1, 9, 0, 0, 102, 105, 108, 101, 58, 47, 47, 47, 12, 0, 0, 0, 1, 1, 0, 0,
            77, 97, 99, 105, 110, 116, 111, 115, 104, 32, 72, 68, 8, 0, 0, 0, 4, 3, 0, 0, 0, 112,
            196, 208, 209, 1, 0, 0, 8, 0, 0, 0, 0, 4, 0, 0, 65, 195, 229, 4, 81, 128, 0, 0, 36, 0,
            0, 0, 1, 1, 0, 0, 57, 54, 70, 66, 52, 49, 67, 48, 45, 54, 67, 69, 57, 45, 52, 68, 65,
            50, 45, 56, 52, 51, 53, 45, 51, 53, 66, 67, 49, 57, 67, 55, 51, 53, 65, 51, 24, 0, 0,
            0, 1, 2, 0, 0, 129, 0, 0, 0, 1, 0, 0, 0, 239, 19, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 47, 0, 0, 0, 0, 0, 0, 0, 1, 5, 0, 0, 204, 0, 0, 0, 254,
            255, 255, 255, 1, 0, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 4, 16, 0, 0, 104, 0, 0, 0, 0, 0, 0,
            0, 5, 16, 0, 0, 192, 0, 0, 0, 0, 0, 0, 0, 16, 16, 0, 0, 232, 0, 0, 0, 0, 0, 0, 0, 64,
            16, 0, 0, 216, 0, 0, 0, 0, 0, 0, 0, 2, 32, 0, 0, 180, 1, 0, 0, 0, 0, 0, 0, 5, 32, 0, 0,
            36, 1, 0, 0, 0, 0, 0, 0, 16, 32, 0, 0, 52, 1, 0, 0, 0, 0, 0, 0, 17, 32, 0, 0, 104, 1,
            0, 0, 0, 0, 0, 0, 18, 32, 0, 0, 72, 1, 0, 0, 0, 0, 0, 0, 19, 32, 0, 0, 88, 1, 0, 0, 0,
            0, 0, 0, 32, 32, 0, 0, 148, 1, 0, 0, 0, 0, 0, 0, 48, 32, 0, 0, 192, 1, 0, 0, 0, 0, 0,
            0, 1, 192, 0, 0, 8, 1, 0, 0, 0, 0, 0, 0, 17, 192, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 18,
            192, 0, 0, 24, 1, 0, 0, 0, 0, 0, 0, 16, 208, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0,
        ];

        let (bookmark_data, header) = BookmarkData::parse_bookmark_header(&data).unwrap();
        let book_sig: u32 = 1802465122;
        let book_length: u32 = 716;
        let book_offset: u32 = 48;
        let book_version: u32 = 1040;
        assert_eq!(header.signature, book_sig);
        assert_eq!(header.bookmark_data_length, book_length);
        assert_eq!(header.bookmark_data_offset, book_offset);
        assert_eq!(header.version, book_version);

        let (_, bookmark) = BookmarkData::parse_bookmark_data(bookmark_data).unwrap();
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
}
