window.onload = () => {
    let form = document.querySelector("form");
    document.addEventListener("submit", async (e) => handleRegisterSubmit(e, form));
    document.querySelector("input#password").addEventListener("input", (e) => checkPassStrength(e));
    document.querySelector('a#logout-btn').addEventListener('click', async (e) => handleLogoutClick(e));
}

const handleRegisterSubmit = async(event, form) => {
    event.preventDefault();
    try {
        let res = await performRegistration(getFormValues(form));
        window.location.pathname = "/login"
        if (res && res.message) {
            flashAlert(res.message, "success")
        }
    } catch (e) {
        flashAlert(e.message);
    }
};

const performRegistration = async (data) => {
    let res = await fetch ("/register", {
        method: "POST",
        body: JSON.stringify(data),
        headers: getHeaders()
    });

    if (res.status === 200) {
        console.log(res)
        return await res.json();
    } else {
        throw await res.json();
    }
}

const checkPassStrength = (e) => {
    let currentPass = e.target.value;
    let pattern1 = /[A-Z]/;
    let pattern2 = /[0-9]/;
    let pattern3 = /[!@#$%^&*()_-]/;
    updatePassStrengthTag(
        (currentPass.match(pattern1) !== null) +
        (currentPass.match(pattern2) !== null) +
        (currentPass.match(pattern3) !== null) +
        (currentPass.length >= 8),
        document.querySelector("p#pass-XI")
    )
};

const updatePassStrengthTag = (value, passStrElement) => {
    let text = "Password strength: "
    console.log(value)
    switch (value) {
        case 0:
            text += "Very weak";
            passStrElement.className = 'weak';
            break;
        case 1:
            text += "Weak";
            passStrElement.className = 'weak';
            break;
        case 2:
            text += "Moderate";
            passStrElement.className = 'moderate';
            break;
        case 3:
            text += "Getting there, but still moderate";
            passStrElement.className = 'moderate';
            break;
        case 4:
            text += "Strong";
            passStrElement.className = 'strong';
            break;
    }
    passStrElement.innerText = text;
};