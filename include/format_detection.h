#ifndef FORMAT_DETECTION_H
#define FORMAT_DETECTION_H

#include <stddef.h>
#include "types.h"

/**
 * Initialize libmagic for file type detection
 * Must be called before using detection functions
 * Returns 0 on success, -1 on failure
 */
int format_detection_init(void);

/**
 * Cleanup libmagic resources
 * Should be called when done with format detection
 */
void format_detection_cleanup(void);

/**
 * Detect MIME type from memory buffer using libmagic
 * Does not require creating disk files
 * 
 * @param data   Pointer to data buffer
 * @param size   Size of data buffer
 * @return       MIME type string (e.g., "application/json")
 */
const char *detect_mime_type(const char *data, size_t size);

/**
 * Detect file type and return enum value
 * 
 * @param data   Pointer to data buffer
 * @param size   Size of data buffer
 * @return       File type enum value
 */
enum file_type_t detect_file_type(const char *data, size_t size);

/**
 * Get human-readable string for file type
 * 
 * @param type   File type enum
 * @return       String representation (e.g., "JSON", "XML")
 */
const char *file_type_to_string(enum file_type_t type);

/**
 * Select appropriate mutation engine based on detected file type
 * 
 * @param type   File type enum
 * @return       Function pointer to mutation handler
 */
void (*select_mutation_engine(enum file_type_t type))(struct state *);

/**
 * Detect format and select engine in one call
 * Convenience function that combines detection and engine selection
 * 
 * @param data      Pointer to data buffer
 * @param size      Size of data buffer
 * @param out_type  Optional pointer to store detected type (can be NULL)
 * @return          Function pointer to mutation handler
 */
void (*detect_and_select_engine(const char *data, size_t size, 
                                 enum file_type_t *out_type))(struct state *);

#endif /* FORMAT_DETECTION_H */
