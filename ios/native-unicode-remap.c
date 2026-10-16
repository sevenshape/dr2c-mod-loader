#include <stdint.h>
#include <stddef.h>

#if defined(__GNUC__)
#define MR2C_EXPORT __attribute__((visibility("default")))
#else
#define MR2C_EXPORT
#endif

typedef int (*glyphs_batch_plot_ex_fn)(void *, const unsigned char *, int, int, int);
typedef void (*sprite_batch_plot_fn)(void *, int, int);
typedef void (*sprite_batch_draw_fn)(void *);
typedef void *(*sprite_get_fn)(short);

static glyphs_batch_plot_ex_fn original_glyph;
static sprite_batch_plot_fn original_sprite;
static sprite_batch_draw_fn draw_batch;
static sprite_get_fn get_sprite;
static unsigned char *turtle_base;
static unsigned char *unicode_sprite;
static void *main_atlas;
static void *font_atlas;
static int unicode_x;
static int unicode_y;
static int unicode_y_offset;
static int sprite_size = 40;

static unsigned char output[4097];
static unsigned char saved[256][40];
static int saved_slots[256];
static unsigned char active_slots[256];
static unsigned char *active_base;
static int active_count;
static int in_glyph_call;

static int decode_utf8(const unsigned char *text, int length, int at,
    unsigned int *codepoint) {
    unsigned char b0 = text[at];
    *codepoint = b0;
    if (b0 >= 0xc2 && b0 < 0xe0 && at + 1 < length) {
        unsigned char b1 = text[at + 1];
        if ((b1 & 0xc0) == 0x80) {
            *codepoint = ((unsigned int)(b0 & 0x1f) << 6) | (b1 & 0x3f);
            return 2;
        }
    } else if (b0 >= 0xe0 && b0 < 0xf0 && at + 2 < length) {
        unsigned char b1 = text[at + 1];
        unsigned char b2 = text[at + 2];
        if ((b1 & 0xc0) == 0x80 && (b2 & 0xc0) == 0x80 &&
            !(b0 == 0xe0 && b1 < 0xa0) && !(b0 == 0xed && b1 >= 0xa0)) {
            *codepoint = ((unsigned int)(b0 & 0x0f) << 12) |
                ((unsigned int)(b1 & 0x3f) << 6) | (b2 & 0x3f);
            return 3;
        }
    }
    return 1;
}

static int is_private_use(unsigned int codepoint) {
    return codepoint >= 0xe000 && codepoint <= 0xf8ff;
}

static int take_candidate(unsigned char used[256], int first, int count) {
    static const int ranges[8] = {65, 90, 97, 122, 48, 57, 32, 126};
    int range;
    for (range = 0; range < 8; range += 2) {
        int byte;
        for (byte = ranges[range]; byte <= ranges[range + 1]; byte++) {
            int slot = byte - first;
            if (slot >= 0 && slot < count && !used[byte]) {
                used[byte] = 1;
                return byte;
            }
        }
    }
    return -1;
}

MR2C_EXPORT void mr2c_unicode_configure(void *sprite_get_address,
    void *sprite_batch_draw_address, void *turtle_address,
    void *main_atlas_address, int record_size, int y_offset) {
    get_sprite = (sprite_get_fn)sprite_get_address;
    draw_batch = (sprite_batch_draw_fn)sprite_batch_draw_address;
    turtle_base = (unsigned char *)turtle_address;
    main_atlas = main_atlas_address;
    sprite_size = record_size;
    unicode_y_offset = y_offset;
}

MR2C_EXPORT void mr2c_unicode_set_originals(void *sprite_original,
    void *glyph_original) {
    original_sprite = (sprite_batch_plot_fn)sprite_original;
    original_glyph = (glyphs_batch_plot_ex_fn)glyph_original;
}

MR2C_EXPORT void mr2c_unicode_set_font(void *sprite, int x, int y,
    void *atlas) {
    unicode_sprite = (unsigned char *)sprite;
    unicode_x = x;
    unicode_y = y;
    font_atlas = atlas;
}

MR2C_EXPORT void mr2c_sprite_batch_plot_wrapper(void *sprite, int flip,
    int batch) {
    if (original_sprite == NULL) return;
    if (active_base != NULL && sprite_size > 0) {
        ptrdiff_t offset = (unsigned char *)sprite - active_base;
        if (offset >= 0 && offset % sprite_size == 0) {
            int slot = (int)(offset / sprite_size);
            if (slot >= 0 && slot < active_count && active_slots[slot]) {
                double *scale_x = (double *)(turtle_base + 0x18);
                double *scale_y = (double *)(turtle_base + 0x20);
                double saved_x = *scale_x;
                double saved_y = *scale_y;
                *scale_x = saved_x * (2.0 / 3.0);
                *scale_y = saved_y * (2.0 / 3.0);
                original_sprite(sprite, flip, batch);
                *scale_x = saved_x;
                *scale_y = saved_y;
                return;
            }
        }
    }
    original_sprite(sprite, flip, batch);
}

MR2C_EXPORT int mr2c_glyphs_batch_plot_ex_wrapper(void *glyphs,
    const unsigned char *text, int byte_count, int alignment, int batch) {
    unsigned char used[256] = {0};
    unsigned char mapped[256];
    unsigned int codepoints[256];
    unsigned char patched[256] = {0};
    int unique = 0;
    int saved_count = 0;
    int first;
    int count;
    int at;
    int out = 0;
    int index;
    int remappable = 0;
    unsigned char *font;

    if (original_glyph == NULL || glyphs == NULL || text == NULL ||
        byte_count < 0 || byte_count > 4096 || in_glyph_call) {
        return original_glyph != NULL
            ? original_glyph(glyphs, text, byte_count, alignment, batch)
            : 0;
    }

    first = *(int *)((unsigned char *)glyphs + 4);
    count = *(unsigned int *)((unsigned char *)glyphs + 8);
    if (first < -128 || first > 255 || count <= 0 || count > 256 ||
        unicode_sprite == NULL || get_sprite == NULL) {
        return original_glyph(glyphs, text, byte_count, alignment, batch);
    }

    for (at = 0; at < byte_count;) {
        unsigned int codepoint;
        int length = decode_utf8(text, byte_count, at, &codepoint);
        if (length == 1) {
            used[text[at]] = 1;
        } else if (!is_private_use(codepoint)) {
            int known = 0;
            remappable = 1;
            for (index = 0; index < unique; index++) {
                if (codepoints[index] == codepoint) {
                    known = 1;
                    break;
                }
            }
            if (!known) {
                if (unique >= 256)
                    return original_glyph(glyphs, text, byte_count, alignment, batch);
                codepoints[unique++] = codepoint;
            }
        }
        at += length;
    }
    if (!remappable)
        return original_glyph(glyphs, text, byte_count, alignment, batch);

    for (index = 0; index < unique; index++) {
        int candidate = take_candidate(used, first, count);
        if (candidate < 0)
            return original_glyph(glyphs, text, byte_count, alignment, batch);
        mapped[index] = (unsigned char)candidate;
    }

    font = (unsigned char *)get_sprite((short)(*(unsigned int *)glyphs & 0x3fff));
    if (font == NULL)
        return original_glyph(glyphs, text, byte_count, alignment, batch);

    active_base = font;
    active_count = count;
    for (index = 0; index < 256; index++) active_slots[index] = 0;

    for (at = 0; at < byte_count;) {
        unsigned int codepoint;
        int length = decode_utf8(text, byte_count, at, &codepoint);
        if (length == 1 || is_private_use(codepoint)) {
            int byte_index;
            for (byte_index = 0; byte_index < length; byte_index++)
                output[out++] = text[at + byte_index];
        } else {
            int map_index = -1;
            int slot;
            unsigned char *target;
            int byte_index;
            for (index = 0; index < unique; index++) {
                if (codepoints[index] == codepoint) {
                    map_index = index;
                    break;
                }
            }
            if (map_index < 0) goto fallback;
            output[out++] = mapped[map_index];
            slot = (int)mapped[map_index] - first;
            if (!patched[slot]) {
                target = font + slot * sprite_size;
                for (byte_index = 0; byte_index < sprite_size; byte_index++)
                    saved[saved_count][byte_index] = target[byte_index];
                saved_slots[saved_count++] = slot;
                patched[slot] = 1;
                active_slots[slot] = 1;
                for (byte_index = 0; byte_index < sprite_size; byte_index++)
                    target[byte_index] = unicode_sprite[byte_index];
                *(unsigned short *)(target + 0) =
                    (unsigned short)(unicode_x + 12 * (codepoint & 255));
                *(unsigned short *)(target + 2) =
                    (unsigned short)(unicode_y + 12 * ((codepoint >> 8) & 255) +
                        unicode_y_offset);
                *(unsigned short *)(target + 4) = 12;
                *(unsigned short *)(target + 6) = 12;
                *(short *)(target + 12) = 8;
            }
        }
        at += length;
    }
    output[out] = 0;

    in_glyph_call = 1;
    original_glyph(glyphs, output, out, alignment, batch);
    if (draw_batch != NULL && main_atlas != NULL && font_atlas != NULL) {
        draw_batch(main_atlas);
        draw_batch(font_atlas);
    }
    in_glyph_call = 0;
    for (index = 0; index < saved_count; index++) {
        unsigned char *target = font + saved_slots[index] * sprite_size;
        int byte_index;
        for (byte_index = 0; byte_index < sprite_size; byte_index++)
            target[byte_index] = saved[index][byte_index];
    }
    for (index = 0; index < 256; index++) active_slots[index] = 0;
    active_base = NULL;
    active_count = 0;
    return byte_count;

fallback:
    for (index = 0; index < saved_count; index++) {
        unsigned char *target = font + saved_slots[index] * sprite_size;
        int byte_index;
        for (byte_index = 0; byte_index < sprite_size; byte_index++)
            target[byte_index] = saved[index][byte_index];
    }
    for (index = 0; index < 256; index++) active_slots[index] = 0;
    active_base = NULL;
    active_count = 0;
    return original_glyph(glyphs, text, byte_count, alignment, batch);
}
