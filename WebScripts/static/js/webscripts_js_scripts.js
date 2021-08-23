/*

    Basic web scripts for WebScript pages.
    Copyright (C) 2021  Maurice Lambert

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
let theme_button = document.createElement("button");

function get_scripts(func = undefined) {
    let xhttp = new XMLHttpRequest();
    xhttp.onreadystatechange = () => {
        if (xhttp.readyState === 4 && xhttp.status === 200) {
            scripts = JSON.parse(xhttp.responseText);

            if (func !== undefined) {
                func(scripts);
                document.getElementById("prevent_no_javascript").style
                    .display = 'none';
            }
        }
    }

    xhttp.open("GET", "/api/", true);
    xhttp.send();
}

function light_mode(class_name = 'light', element = null) {
    let elements = null;

    if (element === null) {
        elements = [
            [
                document.getElementsByTagName('html')[0],
                document.body,
                document.getElementById("webscripts_content"),
            ],
            document.getElementsByClassName('border'),
            document.getElementsByTagName('button'),
            document.getElementsByTagName('input'),
            document.getElementsByTagName('select'),
            document.getElementsByTagName('a'),
            document.getElementsByTagName('td'),
        ];

        let bar = document.getElementById("bar");
        if (bar !== null) {
            elements[0].push(bar);
        }
    } else {
        elements = [
            element.getElementsByClassName('border'),
            element.getElementsByTagName('button'),
            element.getElementsByTagName('input'),
            element.getElementsByTagName('select'),
            element.getElementsByTagName('a'),
            element.getElementsByTagName('td'),
        ];
    }

    for (let i = 0; i < elements.length; ++i) {
        for (let l = 0; l < elements[i].length; ++l) {
            elements[i][l].classList.toggle(class_name);
        }
    }
}

function theme() {
    let theme = localStorage.getItem('theme');

    if (theme === null) {
        if (window.matchMedia('(prefers-color-scheme: dark)').matches ===
            true) {
            theme = "light";
        } else if (window.matchMedia('(prefers-color-scheme: light)')
            .matches === true) {
            theme = "dark";
        }

        let defaults = document.getElementsByClassName("default_theme");

        while (defaults.length > 0) {
            for (let i = 0; i < defaults.length; ++i) {
                defaults[i].classList.toggle("default_theme");
            }

            defaults = document.getElementsByClassName("default_theme");
            console.log(defaults);
        }
    }

    if (theme === "light") {
        localStorage.setItem('theme', 'dark');
        theme_button.innerText = "Light mode";
    } else if (theme === "dark") {
        localStorage.setItem('theme', 'light');
        theme_button.innerText = "Dark mode";
    }

    light_mode();
}

function load_theme() {
    if (localStorage.getItem('theme') === null) {
        light_mode('default_theme');
    } else if (localStorage.getItem('theme') === "light") {
        light_mode();
        theme_button.innerText = "Dark mode";
    }
}

function add_button() {
    let border_left = document.getElementById("webscripts_border_left");

    theme_button.innerText = "Light mode";
    theme_button.onclick = theme;
    theme_button.style.marginBottom = "5%";
    theme_button.style.marginTop = "5%";

    border_left.appendChild(theme_button);
    load_theme();
}