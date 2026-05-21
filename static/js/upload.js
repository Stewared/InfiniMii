function switchTab(tab) {
    document.querySelectorAll(".tab-button").forEach((btn) => {
        const handler = btn.getAttribute("onclick") || "";
        btn.classList.toggle("active", handler.includes(`'${tab}'`));
    });

    document.querySelectorAll(".tab-content").forEach((content) => {
        content.classList.remove("active");
    });

    const tabContent = document.getElementById(`${tab}Tab`);
    if (tabContent) {
        tabContent.classList.add("active");
    }

    syncUploadFormState(tab);
}

function normalizeCodeLength(rawCode) {
    return String(rawCode || "").replace(/\s+/g, "").length;
}

function looksLikeJsonMiiData(rawCode) {
    const trimmed = String(rawCode || "").trim();
    return (trimmed.startsWith("{") && trimmed.endsWith("}"))
        || (trimmed.startsWith("[") && trimmed.endsWith("]"));
}

function showUploadJsonError(form, message) {
    const messageId = form?.id === "officialUploadForm" ? "official-error-message" : "error-message";
    const messageDiv = document.getElementById(messageId);
    if (!messageDiv) {
        return;
    }

    messageDiv.className = "form-message error";
    messageDiv.style.display = "block";
    messageDiv.textContent = message;
    if (typeof window.scrollToUserError === "function") {
        window.scrollToUserError(messageDiv);
    }
}

function normalizeUploadJsonField(form) {
    const codeInput = form?.querySelector?.('textarea[name="miiData"]');
    if (!codeInput || codeInput.disabled) {
        return true;
    }

    const rawCode = codeInput.value.trim();
    if (!rawCode || !looksLikeJsonMiiData(rawCode)) {
        return true;
    }

    try {
        codeInput.value = JSON.stringify(JSON.parse(rawCode));
        return true;
    } catch (error) {
        showUploadJsonError(form, `The pasted MiiJS JSON is not valid JSON: ${error.message}`);
        return false;
    }
}

function updateStudioNameFieldVisibility() {
    const codeInput = document.getElementById("upload-miiData");
    const nameGroup = document.getElementById("upload-miiName-group");
    const nameInput = document.getElementById("upload-miiName");
    const codeTab = document.getElementById("codeTab");

    if (!codeInput || !nameGroup || !nameInput || !codeTab) {
        return;
    }

    const codeLength = normalizeCodeLength(codeInput.value);
    const needsName = !looksLikeJsonMiiData(codeInput.value) && (codeLength === 92 || codeLength === 64);
    const isCodeTabActive = codeTab.classList.contains("active");
    const shouldShow = needsName && isCodeTabActive;

    nameGroup.style.display = shouldShow ? "block" : "none";
    nameInput.required = shouldShow;
    nameInput.disabled = !shouldShow;

    if (!needsName) {
        nameInput.value = "";
    }
}

function syncUploadFormState(tab) {
    const uploadForm = document.getElementById("uploadForm");
    if (uploadForm) {
        uploadForm.classList.toggle("hidden", tab === "qr");
    }

    const fileInput = document.getElementById("mii-upload");
    if (fileInput) {
        fileInput.disabled = tab !== "file";
    }

    const codeInput = document.getElementById("upload-miiData");
    if (codeInput) {
        codeInput.disabled = tab !== "code";
    }

    if (tab !== "code") {
        const nameGroup = document.getElementById("upload-miiName-group");
        const nameInput = document.getElementById("upload-miiName");
        if (nameGroup) {
            nameGroup.style.display = "none";
        }
        if (nameInput) {
            nameInput.required = false;
            nameInput.disabled = true;
        }
        return;
    }

    updateStudioNameFieldVisibility();
}

function assignDroppedUploadFiles(input, files) {
    const selectedFiles = Array.from(files || []);
    if (!input || input.disabled || selectedFiles.length === 0) {
        return;
    }

    const filesToUse = input.multiple ? selectedFiles : selectedFiles.slice(0, 1);

    try {
        if (typeof DataTransfer !== "undefined") {
            const transfer = new DataTransfer();
            filesToUse.forEach((file) => transfer.items.add(file));
            input.files = transfer.files;
        } else {
            input.files = files;
        }

        input.dispatchEvent(new Event("change", { bubbles: true }));
    } catch (error) {
        console.warn("Dropped files could not be assigned to the upload input.", error);
    }
}

function dragEventHasUploadFiles(event) {
    return Array.from(event.dataTransfer?.types || []).includes("Files");
}

function bindUploadFormDrop(formId, inputId) {
    const form = document.getElementById(formId);
    const input = document.getElementById(inputId);

    if (!form || !input) {
        return;
    }

    ["dragenter", "dragover"].forEach((eventName) => {
        form.addEventListener(eventName, (event) => {
            if (input.disabled || !dragEventHasUploadFiles(event)) {
                return;
            }

            event.preventDefault();
        });
    });

    form.addEventListener("drop", (event) => {
        if (input.disabled || !dragEventHasUploadFiles(event)) {
            return;
        }

        event.preventDefault();
        assignDroppedUploadFiles(input, event.dataTransfer?.files);
    });
}

function initializeUploadFormDrops() {
    bindUploadFormDrop("uploadForm", "mii-upload");
    bindUploadFormDrop("officialUploadForm", "official-mii-upload");
}

document.addEventListener("DOMContentLoaded", () => {
    const codeInput = document.getElementById("upload-miiData");
    if (codeInput) {
        codeInput.addEventListener("input", updateStudioNameFieldVisibility);
        codeInput.addEventListener("change", updateStudioNameFieldVisibility);
    }

    initializeUploadFormDrops();
    switchTab("file");
});

document.addEventListener("submit", (event) => {
    const form = event.target;
    if (!["uploadForm", "officialUploadForm"].includes(form?.id)) {
        return;
    }

    if (!normalizeUploadJsonField(form)) {
        event.preventDefault();
        event.stopImmediatePropagation();
    }
}, true);
