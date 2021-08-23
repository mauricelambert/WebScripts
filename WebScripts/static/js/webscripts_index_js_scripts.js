/*

    Scripts for index pages.
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

function build_categories(scripts) {
    let content = document.getElementById("webscripts_content");
    let categories = {};
    let script_string;
    let script;

    for (let i in scripts) {
        script = scripts[i];

        if (script.name !== "/auth/") {
            script_string = `
					<li class="category script_bullet_point"><a class="category script_link inline" href="/web/scripts/${script.name}">${script.name}</a> <p class="description inline">(${script.description})</p></li>
			`
        } else {
            script_string = `
					<li class="category script_bullet_point"><a class="category script_link inline" href="/web/auth/">${script.name}</a> <p class="description inline">(${script.description})</p></li>
			`
        }

        if (script.category !== undefined && categories[script.category] ===
            undefined) {
            categories[script.category] = `
			<div class="category category_content">
				<h3 class="category category_title">${script.category}</h3>

				<ul class="category scripts_list">
					${script_string}
					<!---->
				</ul>
			</div>
			`;
        } else if (script.category !== undefined && categories[script
            .category] !== undefined) {
            categories[script.category] = categories[script.category].replace(
                "<!---->", script_string + "<!---->");
        }
    }

    for (let i in categories) {
        content.innerHTML += categories[i];
    }

    add_button();
}