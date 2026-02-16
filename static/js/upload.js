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
}
