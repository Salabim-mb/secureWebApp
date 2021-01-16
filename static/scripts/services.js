window.onload = () => {
    document.querySelector('a#logout-btn').addEventListener('click', async (e) => handleLogoutClick(e));
    document.querySelectorAll('td#delete-btn').forEach((item) => {
        item.firstElementChild.addEventListener("click", async (e) => deleteEntry(e, item.parentElement))
    });
    document.querySelectorAll('td#pass-td').forEach((item) => {
        item.firstElementChild.addEventListener("click", async(e) => handleGetPassword(e, item.parentElement))
    })
}

const deleteEntry = async (event, el) => {
    event.preventDefault();
    const site = el.firstElementChild.innerText;
    try {
        let res = await performDeletion({
            site: site
        });
        if (res && res.message) {
            flashAlert(res.message, "success");
        }
        window.location.reload(true);
    } catch(e) {
        if (e && e.message) {
            flashAlert(e.message);
        }
    }
};

const performDeletion = async (data) => {
    const url = "/user/my-passwords";
    const res = await fetch(url, {
        method: "DELETE",
        headers: getHeaders(),
        body: JSON.stringify(data)
    });

    if (res.status === 200) {
        return await res.json();
    } else {
        throw await res.json();
    }
};

const handleGetPassword = async (event, el) => {
    event.preventDefault();
    const site = el.firstElementChild.innerText;
    try {
        let res = await fetchPassword(site)
        if (res && res.message && res.password) {
            flashAlert(res.message, "success");
            let old = el.querySelector("td#pass-td").firstElementChild;
            el.querySelector("td#pass-td").removeChild(old);
            let newChild = document.createElement("span");
            newChild.innerText = res.password;
            el.querySelector("td#pass-td").appendChild(newChild)
        }
    } catch(e) {
        if (e && e.message) {
            flashAlert(e.message);
        }
    }
};

const fetchPassword = async (site) => {
    const url = `/user/my-passwords/site/${site}`;
    const res = await fetch(url, {
        method: "GET"
    });

    if (res.status === 200) {
        return await res.json();
    } else {
        throw await res.json();
    }
};