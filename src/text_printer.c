#include "global.h"
#include "main.h"
#include "palette.h"
#include "string_util.h"
#include "window.h"
#include "text.h"

static EWRAM_DATA struct TextPrinter sTempTextPrinter = {0};
static EWRAM_DATA struct TextPrinter sTextPrinters[NUM_TEXT_PRINTERS] = {0};

static u16 sFontHalfRowLookupTable[0x51];
static u16 sLastTextBgColor;
static u16 sLastTextFgColor;
static u16 sLastTextShadowColor;

const struct FontInfo *gFonts;
u8 gGlyphInfo[0x90];

static const u8 sFontHalfRowOffsets[] =
{
    0x00, 0x01, 0x02, 0x00, 0x03, 0x04, 0x05, 0x03, 0x06, 0x07, 0x08, 0x06, 0x00, 0x01, 0x02, 0x00,
    0x09, 0x0A, 0x0B, 0x09, 0x0C, 0x0D, 0x0E, 0x0C, 0x0F, 0x10, 0x11, 0x0F, 0x09, 0x0A, 0x0B, 0x09,
    0x12, 0x13, 0x14, 0x12, 0x15, 0x16, 0x17, 0x15, 0x18, 0x19, 0x1A, 0x18, 0x12, 0x13, 0x14, 0x12,
    0x00, 0x01, 0x02, 0x00, 0x03, 0x04, 0x05, 0x03, 0x06, 0x07, 0x08, 0x06, 0x00, 0x01, 0x02, 0x00,
    0x1B, 0x1C, 0x1D, 0x1B, 0x1E, 0x1F, 0x20, 0x1E, 0x21, 0x22, 0x23, 0x21, 0x1B, 0x1C, 0x1D, 0x1B,
    0x24, 0x25, 0x26, 0x24, 0x27, 0x28, 0x29, 0x27, 0x2A, 0x2B, 0x2C, 0x2A, 0x24, 0x25, 0x26, 0x24,
    0x2D, 0x2E, 0x2F, 0x2D, 0x30, 0x31, 0x32, 0x30, 0x33, 0x34, 0x35, 0x33, 0x2D, 0x2E, 0x2F, 0x2D,
    0x1B, 0x1C, 0x1D, 0x1B, 0x1E, 0x1F, 0x20, 0x1E, 0x21, 0x22, 0x23, 0x21, 0x1B, 0x1C, 0x1D, 0x1B,
    0x36, 0x37, 0x38, 0x36, 0x39, 0x3A, 0x3B, 0x39, 0x3C, 0x3D, 0x3E, 0x3C, 0x36, 0x37, 0x38, 0x36,
    0x3F, 0x40, 0x41, 0x3F, 0x42, 0x43, 0x44, 0x42, 0x45, 0x46, 0x47, 0x45, 0x3F, 0x40, 0x41, 0x3F,
    0x48, 0x49, 0x4A, 0x48, 0x4B, 0x4C, 0x4D, 0x4B, 0x4E, 0x4F, 0x50, 0x4E, 0x48, 0x49, 0x4A, 0x48,
    0x36, 0x37, 0x38, 0x36, 0x39, 0x3A, 0x3B, 0x39, 0x3C, 0x3D, 0x3E, 0x3C, 0x36, 0x37, 0x38, 0x36,
    0x00, 0x01, 0x02, 0x00, 0x03, 0x04, 0x05, 0x03, 0x06, 0x07, 0x08, 0x06, 0x00, 0x01, 0x02, 0x00,
    0x09, 0x0A, 0x0B, 0x09, 0x0C, 0x0D, 0x0E, 0x0C, 0x0F, 0x10, 0x11, 0x0F, 0x09, 0x0A, 0x0B, 0x09,
    0x12, 0x13, 0x14, 0x12, 0x15, 0x16, 0x17, 0x15, 0x18, 0x19, 0x1A, 0x18, 0x12, 0x13, 0x14, 0x12,
    0x00, 0x01, 0x02, 0x00, 0x03, 0x04, 0x05, 0x03, 0x06, 0x07, 0x08, 0x06, 0x00, 0x01, 0x02, 0x00
};

static void RunTextPrintersForInstantText(void);

void SetFontsPointer(const struct FontInfo *fonts)
{
    gFonts = fonts;
}

void DeactivateAllTextPrinters (void)
{
    int printer;
    for (printer = 0; printer < NUM_TEXT_PRINTERS; ++printer)
        sTextPrinters[printer].active = 0;
}

u32 IsInstantText(void) {
    return TRUE;
}

u16 AddTextPrinterParameterized(u8 windowId, u8 fontId, const u8 *str, u8 x, u8 y, u8 speed, void (*callback)(struct TextPrinterTemplate *, u16))
{
    struct TextPrinterTemplate printerTemplate;

    printerTemplate.currentChar = str;
    printerTemplate.windowId = windowId;
    printerTemplate.fontId = fontId;
    printerTemplate.x = x;
    printerTemplate.y = y;
    printerTemplate.currentX = x;
    printerTemplate.currentY = y;
    printerTemplate.letterSpacing = gFonts[fontId].letterSpacing;
    printerTemplate.lineSpacing = gFonts[fontId].lineSpacing;
    printerTemplate.unk = gFonts[fontId].unk;
    printerTemplate.fgColor = gFonts[fontId].fgColor;
    printerTemplate.bgColor = gFonts[fontId].bgColor;
    printerTemplate.shadowColor = gFonts[fontId].shadowColor;
    return AddTextPrinter(&printerTemplate, speed, callback);
}

bool16 AddTextPrinter(struct TextPrinterTemplate *textSubPrinter, u8 speed, void (*callback)(struct TextPrinterTemplate *, u16))
{
    int i;
    u16 j;

    if (!gFonts)
        return FALSE;

    if (IsInstantText() && speed != 0 && speed != TEXT_SPEED_FF) {
        speed = 1;
    }

    sTempTextPrinter.active = 1;
    sTempTextPrinter.state = 0;
    sTempTextPrinter.textSpeed = speed;
    sTempTextPrinter.delayCounter = 0;
    sTempTextPrinter.scrollDistance = 0;

    for (i = 0; i < 7; ++i)
    {
        sTempTextPrinter.subUnion.fields[i] = 0;
    }

    sTempTextPrinter.printerTemplate = *textSubPrinter;
    sTempTextPrinter.callback = callback;
    sTempTextPrinter.minLetterSpacing = 0;
    sTempTextPrinter.japanese = 0;

    GenerateFontHalfRowLookupTable(textSubPrinter->fgColor, textSubPrinter->bgColor, textSubPrinter->shadowColor);
    if (speed != TEXT_SPEED_FF && speed != 0x0)
    {
        --sTempTextPrinter.textSpeed;
        sTextPrinters[textSubPrinter->windowId] = sTempTextPrinter;
    }
    else
    {
        sTempTextPrinter.textSpeed = 0;
        for (j = 0; j < 0x400; ++j)
        {
            if ((u32)RenderFont(&sTempTextPrinter) == 1)
                break;
        }

        if (speed != TEXT_SPEED_FF)
          CopyWindowToVram(sTempTextPrinter.printerTemplate.windowId, 2);
        sTextPrinters[textSubPrinter->windowId].active = 0;
    }
    return TRUE;
}

void RunTextPrinters(void)
{
    int i;
    u16 temp;

    if (IsInstantText()) {
        RunTextPrintersForInstantText();
        return;
    }

    for (i = 0; i < 0x20; ++i)
    {
        if (sTextPrinters[i].active != 0)
        {
            temp = RenderFont(&sTextPrinters[i]);
            switch (temp) {
                case 0:
                    CopyWindowToVram(sTextPrinters[i].printerTemplate.windowId, 2);
                case 3:
                    if (sTextPrinters[i].callback != 0)
                        sTextPrinters[i].callback(&sTextPrinters[i].printerTemplate, temp);
                    break;
                case 1:
                    sTextPrinters[i].active = 0;
                    break;
            }
        }
    }
}

static void RunTextPrintersForInstantText(void) {
    int i, j;
    u16 result;

    for (i = 0; i < 0x20; ++i)
    {
        if (sTextPrinters[i].active != 0)
        {
            for (j = 0; j < 0x400; j++) {
                u32 oldState;
                u32 newState;

                oldState = sTextPrinters[i].state;
                result = RenderFont(&sTextPrinters[i]);
                newState = sTextPrinters[i].state;

                if (result == 0) {
                    if (sTextPrinters[i].callback != 0)
                        sTextPrinters[i].callback(&sTextPrinters[i].printerTemplate, result);
                } else if (result == 3) {
                    if (sTextPrinters[i].callback != 0)
                        sTextPrinters[i].callback(&sTextPrinters[i].printerTemplate, result);
                    if (oldState == 0 && newState != 0)
                        CopyWindowToVram(sTextPrinters[i].printerTemplate.windowId, 2);
                    break;
                } else if (result == 1) {
                    CopyWindowToVram(sTextPrinters[i].printerTemplate.windowId, 2);
                    sTextPrinters[i].active = 0;
                    break;
                }
            }
        }
    }
}

bool16 IsTextPrinterActive(u8 id)
{
    return sTextPrinters[id].active;
}

u32 RenderFont(struct TextPrinter *textPrinter)
{
    u32 ret;
    while (TRUE)
    {
        ret = gFonts[textPrinter->printerTemplate.fontId].fontFunction(textPrinter);
        if (ret != 2)
            return ret;
    }
}

void GenerateFontHalfRowLookupTable(u8 fgColor, u8 bgColor, u8 shadowColor)
{
    int lutIndex;
    int i, j, k, l;
    const u32 colors[] = {bgColor, fgColor, shadowColor};

    sLastTextBgColor = bgColor;
    sLastTextFgColor = fgColor;
    sLastTextShadowColor = shadowColor;

    lutIndex = 0;

    for (i = 0; i < 3; i++)
        for (j = 0; j < 3; j++)
            for (k = 0; k < 3; k++)
                for (l = 0; l < 3; l++)
                    sFontHalfRowLookupTable[lutIndex++] = (colors[l] << 12) | (colors[k] << 8) | (colors[j] << 4) | colors[i];
}

void SaveTextColors(u8 *fgColor, u8 *bgColor, u8 *shadowColor)
{
    *bgColor = sLastTextBgColor;
    *fgColor = sLastTextFgColor;
    *shadowColor = sLastTextShadowColor;
}

void RestoreTextColors(u8 *fgColor, u8 *bgColor, u8 *shadowColor)
{
    GenerateFontHalfRowLookupTable(*fgColor, *bgColor, *shadowColor);
}

void DecompressGlyphTile(const u16 *src, u16 *dest)
{
    int i;

    for (i = 0; i < 16; i++)
    {
        int offsetIndex = (i << 31) ? (u8)*src++ : (*src >> 8);
        dest[i] = sFontHalfRowLookupTable[sFontHalfRowOffsets[offsetIndex]];
    }
}

u8 GetLastTextColor(u8 colorType)
{
    switch (colorType)
    {
        case 0:
            return sLastTextFgColor;
        case 2:
            return sLastTextBgColor;
        case 1:
            return sLastTextShadowColor;
        default:
            return 0;
    }
}
