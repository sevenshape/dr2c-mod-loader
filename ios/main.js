'use strict';

function getDocumentsDirectory() {
    return ObjC.classes.NSFileManager.defaultManager()
        .URLsForDirectory_inDomains_(9, 1)
        .lastObject()
        .path()
        .toString();
}

function writeDiagnostic(message) {
    try {
        const file = new File(
            getDocumentsDirectory() + '/dr2c-autonomous-eval.log',
            'w'
        );
        file.write(message);
        file.flush();
        file.close();
    } catch (e) {
        console.error('[dr2c-loader] unable to write eval diagnostic:', e);
    }
}

function installEarlyButton(label) {
    const mainModule = Process.getModuleByName('DR2C');
    const buttonExAddress = mainModule.base.add(0x54100);
    const mainButtonDataFunc = mainModule.base.add(0x81BBC);
    const buttonEx = new NativeFunction(
        buttonExAddress,
        'pointer',
        ['float', 'float', 'int', 'pointer', 'pointer']
    );
    const buttonText = Memory.allocUtf8String(label);
    const languageText = Memory.allocUtf8String('Language');
    const click = new NativeCallback(() => {
        const target = globalThis.__DR2C_MOD_CALLBACK_PTR__;
        if (target) {
            return new NativeFunction(target, 'uint', [])();
        }
        return 1;
    }, 'uint', []);
    const languageClick = new NativeCallback(() => {
        const target = globalThis.__DR2C_LANG_CALLBACK_PTR__;
        if (target) {
            return new NativeFunction(target, 'uint', [])();
        }
        return 1;
    }, 'uint', []);

    function containsAscii(text, value) {
        if (text.isNull()) return false;
        const needle = [];
        for (let i = 0; i < value.length; i++) needle.push(value.charCodeAt(i));
        for (let i = 0; i < 64; i++) {
            const b = text.add(i).readU8();
            if (b === 0) return false;
            if (b !== needle[0]) continue;
            let match = true;
            for (let j = 1; j < needle.length; j++) {
                if (text.add(i + j).readU8() !== needle[j]) {
                    match = false;
                    break;
                }
            }
            if (match) return true;
        }
        return false;
    }

    function translated(text, translate) {
        if (typeof translate !== 'function') return text;
        try {
            return translate(text);
        } catch (_) {
            return text;
        }
    }

    const replacement = new NativeCallback((x, y, id, text, func) => {
        // full.js installs this bridge after loading the selected language.
        // Keeping translation in this early replacement is essential: hook()
        // deliberately retains us so a second button_ex replacement would not
        // synchronously re-enter Frida on iOS.
        const translate = globalThis.__DR2C_TRANSLATE_BUTTON_TEXT__;
        const displayText = translated(text, translate);
        const result = buttonEx(x, y, id, displayText, func);
        if (containsAscii(text, 'START')) {
            const button = buttonEx(
                x,
                y - 1,
                0,
                translated(buttonText, translate),
                mainButtonDataFunc
            );
            if (!button.isNull()) button.add(256).writePointer(click);
        }
        if (containsAscii(text, 'Fast Text')) {
            const button = buttonEx(
                x,
                y + 2,
                0,
                translated(languageText, translate),
                mainButtonDataFunc
            );
            if (!button.isNull()) button.add(256).writePointer(languageClick);
        }
        return result;
    }, 'pointer', ['float', 'float', 'int', 'pointer', 'pointer']);

    // The full bundle later replaces button_ex itself, but buttons already
    // created by this hook keep the click pointer. Retain all callbacks for
    // the lifetime of the process.
    globalThis.__DR2C_EARLY_BUTTON_CLICK__ = click;
    globalThis.__DR2C_EARLY_LANGUAGE_CLICK__ = languageClick;
    globalThis.__DR2C_EARLY_BUTTON_REPLACEMENT__ = replacement;
    globalThis.__DR2C_EARLY_BUTTON_TEXT__ = buttonText;
    Interceptor.replace(buttonExAddress, replacement);
}

function initializeAutonomousLoader(stage) {
    try {
        // Gadget waits for rpc.exports.init() to return before executing the
        // program entrypoint. Keep every startup-sensitive hook inside this
        // lifecycle method so the statically patched compact definition
        // layout is never visible without its Frida compatibility layer.
        installEarlyButton('Mods');
        // LiveContainer hosts the guest executable inside its own process, so
        // Process.mainModule points at LiveContainer instead of DR2C. Resolve
        // resources relative to the guest module that we already hooked.
        const appPath = Process.getModuleByName('DR2C').path;
        const appDirectory = appPath.substring(0, appPath.lastIndexOf('/'));
        const fullSource = File.readAllText(appDirectory + '/Frameworks/full.js');
        (0, eval)(fullSource);
        if (globalThis.__DR2C_BOOT_ERROR__)
            throw new Error(String(globalThis.__DR2C_BOOT_ERROR__));
        writeDiagnostic(
            'full.js evaluated successfully\n' +
            'gadget stage: ' + String(stage) + '\n' +
            'mods callback ready: ' + Boolean(globalThis.__DR2C_MOD_CALLBACK_PTR__) + '\n' +
            'boot stage: ' + String(globalThis.__DR2C_BOOT_STAGE__) + '\n' +
            'boot error: ' + String(globalThis.__DR2C_BOOT_ERROR__)
        );
    } catch (e) {
        const detail = e && e.stack ? e.stack : String(e);
        writeDiagnostic('full.js failed:\n' + detail);
        console.error('[dr2c-loader] full.js failed:', detail);
        throw e;
    }
}

rpc.exports = {
    init(stage) {
        initializeAutonomousLoader(stage);
    }
};
