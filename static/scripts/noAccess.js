window.onload = () => {
    document.querySelector("a#wrong-redir").addEventListener("click", (e) => anonymize(e))
    document.querySelector('a#logout-btn').addEventListener('click', async (e) => handleLogoutClick(e));
}

const anonymize = (e) => {
    e.preventDefault();
    document.cookie = "";
    window.location.pathname = "";
}