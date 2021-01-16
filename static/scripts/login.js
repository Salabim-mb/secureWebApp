window.onload = () => {
    let form = document.querySelector("form");
    document.addEventListener("submit", async (e) => handleLoginSubmit(e, form));
}

const handleLoginSubmit = async(event, form) => {
    event.preventDefault();
    try {
        let res = await performLogin(getFormValues(form));
        if (res.message) {
            flashAlert(res.message, "success")
        }
        window.location.pathname = "/user"
    } catch (e) {
        flashAlert(e.message);
    }
};

const performLogin = async (data) => {
    let res = await fetch ("/login", {
        method: "POST",
        body: JSON.stringify(data),
        headers: getHeaders()
    });

    if (res.status === 200) {
        return await res.json();
    } else {
        throw await res.json();
    }
}