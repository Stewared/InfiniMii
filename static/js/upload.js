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

function updateStudioNameFieldVisibility() {
    const codeInput = document.getElementById("upload-miiData");
    const nameGroup = document.getElementById("upload-miiName-group");
    const nameInput = document.getElementById("upload-miiName");
    const codeTab = document.getElementById("codeTab");

    if (!codeInput || !nameGroup || !nameInput || !codeTab) {
        return;
    }

    const needsName = normalizeCodeLength(codeInput.value) === 92;
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

document.addEventListener("DOMContentLoaded", () => {
    const codeInput = document.getElementById("upload-miiData");
    if (codeInput) {
        codeInput.addEventListener("input", updateStudioNameFieldVisibility);
        codeInput.addEventListener("change", updateStudioNameFieldVisibility);
    }

    switchTab("file");
});
