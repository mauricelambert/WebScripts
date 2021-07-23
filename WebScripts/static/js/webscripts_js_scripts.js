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

function get_scripts (func = undefined) {
	let xhttp = new XMLHttpRequest();
	xhttp.onreadystatechange = () => {
		if (xhttp.readyState === 4 && xhttp.status === 200) {
			scripts = JSON.parse(xhttp.responseText);

			if (func !== undefined) {
				func(scripts);
				document.getElementById("prevent_no_javascript").style.display='none';
			}
		}
	}

	xhttp.open("GET", "/api/", true);
	xhttp.send();
}
