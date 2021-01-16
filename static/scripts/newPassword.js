window.onload = () => {
    document.querySelector('a#logout-btn').addEventListener('click', async (e) => handleLogoutClick(e));
    const form = document.querySelector("form");
    document.addEventListener("submit", async(e) => handleAddCredentials(e, form))
};

const handleAddCredentials = async (e, form) => {
    e.preventDefault();
    const data = getFormValues(form);
    try {
        const res = performCredAddition(data);
        if (res && res.message) {
            flashAlert(res.message, "success");
        }
        window.location.pathname = "/user/my-passwords";
    } catch (e) {
        if (e && e.message) {
            flashAlert(e.message);
        }
    }
};

const performCredAddition = async (data) => {
    const url = "/user/my-passwords/new-password";
    const res = await fetch(url, {
        method: "POST",
        headers: getHeaders(),
        body: JSON.stringify(data)
    });

    if (res.status === 200) {
        return await res.json();
    } else {
        throw await res.json();
    }
};