#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <magic.h>
#include "types.h"
#include "format_detection.h"

/* Global libmagic handle */
static magic_t magic_handle = NULL;

/**
 * Initialize libmagic for file type detection
 * Returns 0 on success, -1 on failure
 */
int format_detection_init(void) {
    if (magic_handle) {
        return 0; /* Already initialized */
    }

    magic_handle = magic_open(MAGIC_MIME_TYPE | MAGIC_NO_CHECK_COMPRESS);
    if (!magic_handle) {
        fprintf(stderr, "[!] Failed to initialize libmagic\n");
        return -1;
    }

    if (magic_load(magic_handle, NULL) != 0) {
        fprintf(stderr, "[!] Failed to load magic database: %s\n", 
                magic_error(magic_handle));
        magic_close(magic_handle);
        magic_handle = NULL;
        return -1;
    }

    return 0;
}

/**
 * Cleanup libmagic resources
 */
void format_detection_cleanup(void) {
    if (magic_handle) {
        magic_close(magic_handle);
        magic_handle = NULL;
    }
}

/**
 * Detect file type from memory buffer using libmagic
 * Returns MIME type string (e.g., "application/json", "image/jpeg")
 * Returns "application/octet-stream" on error
 */
const char *detect_mime_type(const char *data, size_t size) {
    if (!magic_handle) {
        if (format_detection_init() != 0) {
            return "application/octet-stream";
        }
    }

    if (!data || size == 0) {
        return "application/octet-stream";
    }

    const char *mime = magic_buffer(magic_handle, data, size);
    if (!mime) {
        fprintf(stderr, "[!] libmagic detection failed: %s\n", 
                magic_error(magic_handle));
        return "application/octet-stream";
    }

    return mime;
}

/**
 * Map MIME type to internal file type enum
 */
static enum file_type_t mime_to_file_type(const char *mime) {
    if (!mime) {
        return file_type_plain;
    }

    /* JSON detection */
    if (strstr(mime, "json") || strstr(mime, "application/json")) {
        return file_type_json;
    }

    /* XML detection */
    if (strstr(mime, "xml") || strstr(mime, "application/xml") ||
        strstr(mime, "text/xml")) {
        return file_type_xml;
    }

    /* CSV detection */
    if (strstr(mime, "csv") || strstr(mime, "text/csv")) {
        return file_type_csv;
    }

    /* JPEG/image detection */
    if (strstr(mime, "jpeg") || strstr(mime, "image/jpeg") ||
        strstr(mime, "jpg") || strstr(mime, "image/jpg")) {
        return file_type_jpeg;
    }

    /* ELF binary detection */
    if (strstr(mime, "application/x-executable") ||
        strstr(mime, "application/x-sharedlib") ||
        strstr(mime, "application/x-object")) {
        return file_type_elf;
    }

    /* PDF detection */
    if (strstr(mime, "pdf") || strstr(mime, "application/pdf")) {
        return file_type_pdf;
    }

    /* Plain text or unknown */
    if (strstr(mime, "text/")) {
        return file_type_plain;
    }

    /* Default to plain for unknown types */
    return file_type_plain;
}

/**
 * Detect file type and return enum value
 * This is the main entry point for format detection
 */
enum file_type_t detect_file_type(const char *data, size_t size) {
    const char *mime = detect_mime_type(data, size);
    enum file_type_t type = mime_to_file_type(mime);
    
    return type;
}

/**
 * Get human-readable string for file type
 */
const char *file_type_to_string(enum file_type_t type) {
    switch (type) {
        case file_type_json:
            return "JSON";
        case file_type_xml:
            return "XML";
        case file_type_csv:
            return "CSV";
        case file_type_jpeg:
            return "JPEG";
        case file_type_elf:
            return "ELF";
        case file_type_pdf:
            return "PDF";
        case file_type_plain:
        default:
            return "Plain Text";
    }
}

/**
 * Select appropriate mutation engine based on detected file type
 * Returns function pointer to the mutation handler
 */
void (*select_mutation_engine(enum file_type_t type))(struct state *) {
    /* Declare external mutation handlers */
    extern void fuzz_handle_json(struct state *);
    extern void fuzz_handle_xml(struct state *);
    extern void fuzz_handle_csv(struct state *);
    extern void fuzz_handle_jpeg(struct state *);
    extern void fuzz_handle_elf(struct state *);
    extern void fuzz_handle_pdf(struct state *);
    extern void fuzz_handle_plaintext(struct state *);

    switch (type) {
        case file_type_json:
            return fuzz_handle_json;
        case file_type_xml:
            return fuzz_handle_xml;
        case file_type_csv:
            return fuzz_handle_csv;
        case file_type_jpeg:
            return fuzz_handle_jpeg;
        case file_type_elf:
            return fuzz_handle_elf;
        case file_type_pdf:
            return fuzz_handle_pdf;
        case file_type_plain:
        default:
            return fuzz_handle_plaintext;
    }
}

/**
 * Detect format and select engine in one call
 * Convenience function that combines detection and engine selection
 */
void (*detect_and_select_engine(const char *data, size_t size, 
                                 enum file_type_t *out_type))(struct state *) {
    enum file_type_t type = detect_file_type(data, size);
    
    if (out_type) {
        *out_type = type;
    }
    
    return select_mutation_engine(type);
}
