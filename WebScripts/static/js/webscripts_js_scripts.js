/*

    Basic web scripts for WebScript pages.
    Copyright (C) 2021, 2022  Maurice Lambert

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.

*/

let scripts;
let is_index = false;
let url = new URL(window.location);
let dark_theme = window.matchMedia("(prefers-color-scheme: dark)").matches;

/*
This class implements a script object.
*/
class Script {
    constructor (script) {
        let name = this.name = script.name;
        this.name_lower = name.toLowerCase();

        let category = this.category = script.category;
        this.category_lower = category.toLowerCase();

        let description = this.description = script.description;
        this.description_lower = description.toLowerCase();

        this.arguments = script.args;

        this.scripts[name] = this;
    }

    /*
    This function builds the script "cards" for the index page and the search bar results.
    */
    build_card (attribut, ...classes) {
        let doc_createElement = document.createElement.bind(document);
        let link_script_card = this[attribut] = doc_createElement("a");
        let div_script_card = doc_createElement("div");
        let classList = div_script_card.classList;
        let div_class_list_add = classList.add.bind(classList);
        let append_child = div_script_card.appendChild.bind(div_script_card);
        let name = this.name;

        if (name === "/auth/") {
            link_script_card.href = "/web/auth/";
        } else {
            link_script_card.href = "/web/scripts/" + name;
        }

        link_script_card.style.textDecoration = 'none';

        for (let class_ of classes) {
            div_class_list_add(class_);
        }

        let title = doc_createElement("h4");
        title.innerText = name + " (" + this.category + ")";

        let description = doc_createElement("p");
        description.innerText = this.description;
        description.classList.add("search_result_description");

        append_child(title);
        append_child(description);
        link_script_card.appendChild(div_script_card);
    }

    /*
    This function implements the search method to research a script,
    on a script page or/and the index page.
    */
    search () {
        let getElementById = document.getElementById.bind(document);

        let path = url.pathname;
        let path_split = path.split('/');
        let path_search = path.startsWith("/web/") && path_split.length === 3 && path_split[2];
        let search_value = getElementById("webscripts_search_bar").value;
        let pattern = search_value || path_search || "";
        pattern = pattern.toLowerCase();

        let search_result_container = getElementById("search_result");
        let result_container_appendChild = search_result_container.appendChild.bind(search_result_container);

        let container = getElementById("webscripts_content");
        let container_appendChild = container.appendChild.bind(container);

        let used_categories = new Set();
        let used_categories_add = used_categories.add.bind(used_categories);
        let used_categories_has = used_categories.has.bind(used_categories);
        let categories = Script.prototype.categories;

        if (is_index) {
            container.innerHTML = "";
        }

        search_result_container.innerHTML = "";

        if (search_value) {
            search_result_container.style.display = 'initial';

        } else {
            search_result_container.style.display = 'none';
        }

        let no_result = true;

        for (let script of Object.values(Script.prototype.scripts)) {
            let category_name = script.category;
            if (script.name_lower.includes(pattern) || script.category_lower.includes(pattern) || script.description_lower.includes(pattern)) {
                if (is_index && category_name) {
                    no_result = false;
                    let category = categories[category_name];
                    category.appendChild(script.link_card);

                    if (!used_categories_has(category_name)) {
                        used_categories_add(category_name);
                        container_appendChild(category);
                    }
                }

                if (search_value) {
                    console.log(script.search_button);
                    result_container_appendChild(script.search_button);
                }
            }
        }

        if (path_search && no_result) {
            container.innerHTML = "<center><p><strong>There is no script matching your search.</strong></p></center>";
        }
    }

    /*
    This function builds the script category if not exists.
    */
    build_category () {
        let category = this.category;
        let categories = this.categories;
        if (category && !categories.hasOwnProperty(category)) {
            let doc_createElement = document.createElement.bind(document);
            let div_category = categories[category] = doc_createElement("div");
            let dic_classList = div_category.classList;
            let div_class_list_add = dic_classList.add.bind(dic_classList);

            div_class_list_add("category");
            // div_class_list_add("category_content");

            let title = doc_createElement("h3");
            let title_classList = title.classList;
            let title_class_list_add = title_classList.add.bind(title_classList);
            title_class_list_add("category");
            title_class_list_add("category_title");
        }
    }

    /*
    This function is a "constructor" to build all scripts.
    */
    build_scripts (scripts) {
        for (let script_basic of Object.values(scripts)) {
            let script = new Script(script_basic);
            script.build_category();
            script.build_card("link_card", "script_cards", "category_content"); // "category"
            script.build_card("search_button", "search_result");
        }

        Script.prototype.search();
    }
}

Script.prototype.categories = {};
Script.prototype.scripts = {};

function get_scripts(...functions) {
    let xhttp = new XMLHttpRequest();
    xhttp.onreadystatechange = () => {
        if (xhttp.readyState === 4 && xhttp.status === 200) {
            scripts = JSON.parse(xhttp.responseText);
            Script.prototype.build_scripts(scripts);

            for (let func of functions) {
                if (func) {
                    func();
                }
            }
        }
    };

    xhttp.open("GET", "/api/", true);
    xhttp.send();
}

/*
This class implements theme functions.
*/
class Theme {

    constructor() {
        this.button = document.getElementById("webscripts_theme_button");
    }

    /*
    This function gets elements from the web page and changes the theme of each.
    */
    change_elements(class_name = 'light', element = null) {
        let elements = null;

        if (element === null) {
            let getElementsByTagName = document.getElementsByTagName.bind(document);
            let getElementByClass = document.getElementsByClassName.bind(document);
            let getElementById = document.getElementById.bind(document);

            elements = [
                getElementsByTagName('html')[0],
                document.body,
                getElementById("webscripts_content"),
                getElementById("webscripts_menu"),
                ...getElementByClass('border'),
                ...getElementByClass('category'),
                ...getElementByClass('category_content'),
                ...getElementByClass('webscripts_column_select'),
                ...getElementByClass('search_result_description'),
                ...getElementsByTagName('button'),
                ...getElementsByTagName('input'),
                ...getElementsByTagName('select'),
                ...getElementsByTagName('a'),
                ...getElementsByTagName('td'),
                ...getElementsByTagName('option'),
                ...getElementsByTagName('progress'),
            ];

            let bar = getElementById("bar");
            if (bar !== null) {
                elements.push(bar);
            }
        } else {
            let getElementsByTagName = element.getElementsByTagName.bind(element);

            elements = [
                ...element.getElementsByClassName('webscripts_column_select'),
                ...element.getElementsByClassName('border'),
                ...getElementsByTagName('button'),
                ...getElementsByTagName('input'),
                ...getElementsByTagName('select'),
                ...getElementsByTagName('a'),
                ...getElementsByTagName('td'),
            ];
        }

        for (let temp_element of elements) {
            temp_element.classList.toggle(class_name);
        }
    }

    /*
    This function reverses the theme of the Web page.
    */
    reverse() {
        let theme = localStorage.getItem('theme');

        if (theme === "light") {
            dark_theme = true;
            localStorage.setItem('theme', 'dark');
            this.button.innerText = "Light theme";
        } else if (theme === "dark") {
            dark_theme = false;
            localStorage.setItem('theme', 'light');
            this.button.innerText = "Dark theme";
        }

        Theme.prototype.change_elements();
    }

    /*
    This function changes the theme when the page loads.
    */
    load() {
        if ((localStorage.getItem('theme') === null && dark_theme) || localStorage.getItem('theme') === "dark") {
            localStorage.setItem('theme', 'dark');
        } else if (localStorage.getItem('theme') === "light" || localStorage
            .getItem('theme') === null) {
            localStorage.setItem('theme', 'light');
            Theme.prototype.change_elements();
            this.button.innerText = "Dark theme";
        } else {
            localStorage.setItem('theme', 'dark');
        }
    }
}

/*
This class builds the header sticker.
*/
class HeaderSticker {
    constructor() {
        let canvas = this.canvas = document.createElement("canvas");
        canvas.id = "webscripts_header_canvas_image";

        let height = this.height = document.getElementById('webscripts_header_text_position').offsetHeight;
        canvas.style.height = height + "px";

        this.context = canvas.getContext("2d");

        let image = this.image = new Image();
        image.onload = this.add.bind(this);
        image.src = '/static/webscripts_icon.png';
    }

    /*
    This method adds the sticker to the header of the web page.
    */
    add() {
        let context = this.context;
        let image = this.image;
        let height = this.height;
        let divise = image.height / height;
        let width = Math.round(image.width / divise);
        let canvas = this.canvas;

        let start_x = Math.round((canvas.width - 200) / 2);
        let start_y = Math.round((canvas.height - 160) / 2);

        context.drawImage(image, start_x, start_y, 200, 160);
        let sticker = this.effect(20);
        context.drawImage(sticker, start_x, start_y, 200, 160);

        let container = document.getElementById('webscripts_header_canvas_container');
        container.style.height = height + "px";
        container.appendChild(this.canvas);
    }

    /*
    This method builds the sticker effect.
    */
    effect (grow) {
        let canvas1 = document.createElement("canvas");
        let context1 = canvas1.getContext("2d");
        let canvas2 = document.createElement("canvas");
        let context2 = canvas2.getContext("2d");
        let image = this.image;

        canvas1.width = canvas2.width = image.width + grow * 2;
        canvas1.height = canvas2.height = image.height + grow * 2;
        context1.drawImage(image, grow, grow);
        context2.shadowColor = 'white';
        context2.shadowBlur = 2;

        for(let i = 0;i < grow; i++){
            context2.drawImage(canvas1, 0, 0);
            context1.drawImage(canvas2, 0, 0);
        }

        context2.shadowColor = 'rgba(0,0,0,0)';
        context2.drawImage(image, grow, grow);

        this.sticker = canvas2;
        return canvas2;
    }
}

/*
This class implements the button menu actions.
*/
class Menu {

    constructor () {
        this.container = document.getElementById("webscripts_menu_values");
    }

    /*
    This function cleans the console.
    */
    clear() {
        document.getElementById("script_outputs").innerText = "";
        download_text = "";
    }

    /*
    This function go back ton index page.
    */
    index() {
        window.location = new URL("/web/", window.location);
    }

    /*
    This function downloads the console content.
    */
    download() {
        let body = document.body;
        let download_link = document.createElement('a');
        let download_link_set = download_link.setAttribute.bind(download_link);

        download_link_set('href',
            `data:text/${download_type};charset=utf-8,` + encodeURIComponent(
                download_text));
        download_link_set('download', `result_${script_name}` +
            download_extension);

        body.appendChild(download_link);
        download_link.click();
        body.removeChild(download_link);
    }

    /*
    This function shows or hides the buttons.
    */
    change_display() {
        let display = this.container.style.display;

        if (!display || display == "none") {
            this.container.style.display = "inline-block";
        } else {
            this.container.style.display = "none";
        }
    }

    /*
    This function build an URL to relaunch this script execution.
    */
    get_execution_url() {
        let getElementsByTagName = document.getElementsByTagName.bind(document);
        let elements = Array.from(getElementsByTagName('input')).concat(
            Array.from(getElementsByTagName('select')));

        url.search = "";
        let append = url.searchParams.append.bind(url.searchParams)

        for (let element of elements) {
            if (element.name && element.value && element.type !== "password" && element.type !== "file" && element.type !== "submit" && element.type !== "button" && element.name !== "csrf_token") {
                append(element.name, element.value);
            }
        }

        navigator.clipboard.writeText(url.href);
        this.toast("Copied");
    }

    /*
    This function copy the full output.
    */
    copy_output () {
        navigator.clipboard.writeText(download_text);
        this.toast("Copied");
    }

    /*
    This function creates a notify toast.
    */
    toast(text) {
        let toast = document.createElement('div');
        toast.classList.add("toast", "show");
        toast.innerText = text;
        document.body.appendChild(toast);
        setTimeout(() => {document.body.removeChild(toast);}, 3000)
    }
}

class Notification {
    close () {
        this.style.display = "none";
        let notifications = JSON.parse(localStorage.getItem('notifications_closed'));

        if (notifications) {
            notifications.push(this.id);
        } else {
            notifications = [this.id];
        }

        localStorage.setItem('notifications_closed', JSON.stringify(notifications));
    }
}

/*
This function is performed when the Web page is loaded.
*/
window.onload = (first, script_onload=null, ...functions) => {
    let getById = document.getElementById.bind(document);

    let theme = new Theme();
    get_scripts(script_onload, theme.load.bind(theme));

    let header_sticker = new HeaderSticker();

    getById("webscripts_search_bar").onkeyup = Script.prototype.search;

    let menu = new Menu();
    getById("webscripts_menu_button_left").onclick = menu.change_display.bind(menu);
    getById("webscripts_theme_button").onclick = theme.reverse.bind(theme);

    for (let func of functions) {
        func();
    }

    let notifications = new Set(JSON.parse(localStorage.getItem('notifications_closed')));

    if (notifications) {
        for (let notification of notifications) {
            let div = getById(notification)

            if (div) {
                div.style.display = "none";
            } else {
                notifications.delete(notification);
            }
            
        }
    }

    localStorage.setItem('notifications_closed', JSON.stringify([...notifications]));

    notifications = document.getElementsByClassName('notification_close');

    for (let notification of notifications) {
        notification.onclick = Notification.prototype.close.bind(notification.parentNode);
    }
}