/*

        Scripts for script.html
        Copyright (C) 2021, 2022  Maurice Lambert

        This program is free software: you can redistribute it and/or modify
        it under the terms of the GNU General Public License as published by
        the Free Software Foundation, either version 3 of the License, or
        (at your option) any later version.

        This program is distributed in the hope that it will be useful,
        but WITHOUT ANY WARRANTY; without even the implied warranty of
        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.    See the
        GNU General Public License for more details.

        You should have received a copy of the GNU General Public License
        along with this program.    If not, see <https://www.gnu.org/licenses/>.

*/

let script_name;
let script;
let download_extension = ".txt";
let download_text = "";
let download_type = "plain";
let download_separator = "\n";
let execution_number = 0;

/*
This class implements an argument.
*/
class Argument {
    constructor(argument) {
        let container = this.container = document.createElement("div");
        this.javascript_attributs = argument.javascript_attributs;
        this.predefined_values = argument.predefined_values;
        this.label = document.createElement("label");
        this.default_value = argument.default_value;
        this.description = argument.description;
        this.is_advanced = argument.is_advanced;
        this.html_type = argument.html_type;
        this.example = argument.example;
        this.name = argument.name;
        this.list = argument.list;

        container.classList.add("row");
    }

    /*
    This method groups arguments elements.
    */
    group_argument_elements(...dom_elements) {
        let container = this.container;
        let appendChild = container.appendChild.bind(container);

        for (let element of dom_elements) {
            appendChild(element);
        }

        return container;
    }

    /*
    This method adds the description if exists.
    */
    add_description() {
        let description = this.description;

        if (description === undefined && description === null) {
            return;
        }

        let paragraph = document.createElement("p");
        let classList = paragraph.classList;
        let add = classList.add.bind(classList);

        add("inline");
        add("description");
        add("script_presentation");

        paragraph.innerText = description;

        return paragraph;
    }

    /*
    This method adds the label (argument name).
    */
    add_label() {
        let name = this.name;
        let label = this.label;
        let classList = label.classList;
        let add_class = classList.add.bind(classList);

        label.htmlFor = name;
        label.innerText = name + " :";
        add_class("inline");
        add_class("script_presentation");

        return label;
    }

    /*
    This method generates argument values
    when this argument has predefined values.
    */
    build_select() {
        let select = this.dom_value = document.createElement("select");
        let default_value = this.default_value;
        let name = this.name;
        let option;

        let appendChild = select.appendChild.bind(select);
        select.name = name;
        select.id = name;

        if (this.list) {
            select.multiple = true;
        }

        if (default_value !== undefined && default_value !== null) {
            select.value = default_value;
        }

        for (let value of this.predefined_values) {
            option = document.createElement("option");
            option.value = option.innerText = value;

            appendChild(option);
        }

        return select;
    }

    /*
    This method builds the argument input.
    */
    build_input() {
        let input = this.dom_value = document.createElement("input");
        let default_value = this.default_value;
        let example = this.example;
        let name = this.name;

        input.id = name;
        input.name = name;
        input.type = this.html_type;

        input.value = default_value || "";
        input.placeholder = example || "";

        if (this.list) {
            input.id = name + document.getElementsByName(name).length;
            input.onkeyup = this.onchange_input_list.bind(input);
        }

        return input;
    }

    /*
    This method implements the onchange event to have multiple values for
    an argument.
    */
    onchange_input_list(event) {
        let source = event.target || event.srcElement;
        let name = source.name;

        let elements = document.getElementsByName(name);
        let one_empty = false;

        for (let element of elements) {
            if (element.value === "" && one_empty) {
                element.remove()
            } else if (element.value === "") {
                one_empty = true;
            }
        }

        if (!one_empty) {
            let id_num = elements.length;
            let id = name + id_num;
            let element = document.getElementById(id);

            while (element) {
                id_num++;
                id = name + id_num;
                element = document.getElementById(id);
            }

            let new_element = source.cloneNode();
            new_element.id = id;
            source.parentNode.appendChild(new_element);
            new_element.onkeyup = this.onkeyup.bind(new_element);
            new_element.value = "";
        }
    }
}

/*
This class implements the script interface.
*/
class ScriptInterface {
    constructor(name) {
        this.name = name;
        this.script = Script.prototype.scripts[name];

        let getElementById = document.getElementById.bind(document);
        this.advanced_button = getElementById("print_advanced");
        this.description_container = getElementById("script_description");
        this.advanced_arguments_container = getElementById(
            "advanced_container");
        let script_container = this.script_container = getElementById(
            "script_interface");
        let advanced_arguments = this.advanced_arguments = getElementById(
            "advanced_arguments");

        this.advanced_arguments_add = advanced_arguments.appendChild.bind(
            advanced_arguments);
        this.insert_argument = script_container.insertBefore.bind(
            script_container);
    }

    /*
    This method adds the script description on the web page.
    */
    add_description() {
        this.description_container.innerText = this.script.description;
    }

    /*
    This method sets HTML/CSS custom attributes.
    */
    set_custom_attributes(dom_element, attributes) {
        for (let [attribute, value] of Object.entries(attributes)) {
            dom_element.setAttribute(attribute, value);
        }
    }

    /*
    This method hides the advanced arguments container
    or defined the button behavior.
    */
    config_advanced_arguments() {
        let advanced_arguments_container = this
        .advanced_arguments_container;
        if (!advanced_arguments_container.getElementsByClassName("row")
            .length) {
            advanced_arguments_container.style.display = "none";
        } else {
            let arguments_ = this.advanced_arguments;
            let button = this.advanced_button;
            button.onclick = () => {
                if (arguments_.style.display &&
                    arguments_.style.display !== "none") {
                    arguments_.style.display = "none";
                    button.innerText = "Show advanced arguments";
                } else {
                    arguments_.style.display = "block";
                    button.innerText = "Hide advanced arguments";
                }
            };
        }
    }

    /*
    This method sets values stocked in URL query string.
    */
    set_url_values() {
        let event;
        let element, element_id;
        let query = location.search;
        let counters = {};

        query = query.substr(1);
        query.split("&").forEach(function(part) {
            let item = part.split("=");
            element_id = element = decodeURIComponent(item[0].replaceAll("+",
                " "));
            counters[element] = counters[element] ? counters[element] : 0;

            if (element) {
                element = document.getElementById(element) || document.getElementById(element + counters[element]);
                counters[element_id] += 1;

                if (element) {
                    if (element.type === "checkbox" && item[1] ===
                        "on") {
                        element.checked = true;
                    } else {
                        element.value = decodeURIComponent(item[1]
                            .replaceAll("+", " "));
                        event = new Event('change');
                        element.dispatchEvent(event);
                    }

                    if (element.onkeyup) {
                        element.onkeyup({'target': element})
                    }
                }
            }
        });
    }

    /*
    This method adds script arguments in web interface.
    */
    add_arguments() {
        for (let argument of this.script.arguments) {
            let dom_argument;
            argument = new Argument(argument);
            let container = document.createElement("div");
            let classList = container.classList;
            let addClass = classList.add.bind(classList);

            addClass("argument_container");
            addClass("inline");

            dom_argument = (argument.predefined_values !== undefined &&
                    argument.predefined_values !== null) ? argument
                .build_select() : argument.build_input();

            dom_argument.addEventListener('keypress', (event) => {
                if (event.keyCode === 13) {
                    ScriptExecution.prototype.start();
                }
            });

            this.set_custom_attributes(dom_argument, argument
                .javascript_attributs);

            container.appendChild(dom_argument);

            let label = argument.add_label(dom_argument);
            let paragraph = argument.add_description();
            let elements_container = argument.group_argument_elements(label,
                paragraph, container);

            argument.is_advanced ? this.advanced_arguments_add(
                elements_container) : this.insert_argument(
                elements_container, this.advanced_arguments_container);
        }
    }
}

/*
Add a function to run when the Web page is loaded.
*/
let onload2 = window.onload;
window.onload = (first, script_onload = null, ...functions) => {
    onload2(window, script_onload = () => {
        script = new ScriptInterface(script_name);

        script.add_description();
        script.add_arguments();

        script.set_url_values();
        script.config_advanced_arguments();

        document.getElementById("submit_button").onclick =
            ScriptExecution.prototype.start;

        let menu = new Menu();
        let history = new History();
        document.getElementById("webscripts_copy_execution_button")
            .onclick = menu.get_execution_url.bind(menu);
        document.getElementById("webscripts_menu_button_right")
            .onclick = history.change_display.bind(history);
        document.getElementById("webscripts_copy_output_button")
            .onclick = menu.copy_output.bind(menu);
        document.getElementById("webscripts_download_button")
            .onclick = menu.download.bind(menu);
        document.getElementById("webscripts_index_button").onclick =
            menu.index.bind(menu);
        document.getElementById("webscripts_clear_button").onclick =
            menu.clear.bind(menu);
    });
};

/*
This class implements object and methods to run scripts.
*/
class ScriptExecution {
    constructor() {
        let getElementsByTagName = document.getElementsByTagName.bind(
            document);
        let getElementById = document.getElementById.bind(document);
        this.dom_arguments = Array.from(getElementsByTagName('input'))
            .concat(
                Array.from(getElementsByTagName('select')));
        this.script_container = getElementById("script_interface");
        this.start_button = getElementById("submit_button");
        this.progressbar = getElementById("progressbar");
        this.error_container = getElementById("error");
        this.csrf = getElementById("csrf_token");
        this.progress_position = 0;
        this.first_ouput = false;
        this.is_running = false;
        this.full_output = "";
        this.progress = true;
        this.full_error = "";
        this.arguments = {};
        this.start = null;
        this.time = null;
        this.counter = 0;
        this.end = null;
    }

    /*
    This method stringify the request body.
    */
    send_json_request() {
        this.send_requests({
            "csrf_token": this.csrf.value,
            "arguments": this.arguments,
        });
    }

    /*
    This method gets a new DOM element and calls the
    argument handler to get the value or prepares the
    body and sends the request.
    */
    get_argument_value() {
        let argument = this.dom_arguments.pop();

        if (argument) {
            this.counter++;
            this[`get_${argument.tagName}_value`](argument);
        } else {
            this.sort_arguments();
            this.send_json_request();
            this.start_button.disabled = true;
            return;
        }
    }

    /*
    Method handler for null arguments.
    */
    get_NULL_value() {}

    /*
    This method sorts arguments to send a valid request.
    */
    sort_arguments() {
        let sort = [];

        for (let [name, argument] of Object.entries(this.arguments)) {
            sort.push([name, argument, argument["position"]]);
        }

        sort.sort(function(a, b) {
            return a[2] - b[2];
        });

        let arguments_ = this.arguments = {};

        for (let [name, argument, position] of sort) {
            arguments_[name] = {
                "value": argument["value"],
                "input": argument["input"]
            };
        }
    }

    /*
    This method is the onclick function for
    start button (create a new instance
    of ScriptExecution and use it).
    */
    start(event) {
        let script_exec = new ScriptExecution();
        script_exec.get_argument_value();
    }

    /*
    This method animates the progress bar.
    */
    progress_animation() {
        let test, operation;

        if (progressbar.value >= 100) {
            test = (value) => {
                return value <= 0;
            }
            operation = (value) => {
                return value - 1;
            }
        } else {
            test = (value) => {
                return value >= 100;
            }
            operation = (value) => {
                return value + 1;
            }
        }

        if (this.progress) {
            this.progress = false;
            let interval = setInterval(() => {
                let progressbar = this.progressbar;
                if (test(progressbar.value)) {
                    clearInterval(interval);
                    this.progress = true;

                    if (this.is_running) {
                        this.progress_animation();
                    }
                } else {
                    progressbar.value = operation(progressbar
                    .value);
                }
            }, 20);
        }
    }

    /*
    This method gets input values.
    */
    get_INPUT_value(input) {
        if (input.type === "submit" || input.name === "csrf_token") {
            this.get_argument_value();
            return;
        }

        if (input.type === "checkbox") {
            this.add_argument_value(
                input.id,
                input.name,
                input.checked,
            );
        } else if (input.type === "file") {
            let reader = new FileReader();

            reader.onload = (a) => {
                this.add_argument_value(
                    input.id,
                    input.name,
                    window.btoa(a.target.result),
                );
            };

            if (input.files.length) {
                reader.readAsBinaryString(input.files[0]);
            } else {
                this.get_argument_value();
            }
        } else {
            this.add_argument_value(
                input.id,
                input.name,
                input.value,
            );
        }
    }

    /*
    This method gets select values.
    */
    get_SELECT_value(select) {
        let dom_arguments = this.dom_arguments;
        let selected = [];
        let first = true;

        for (let option of select.options) {
            if (option.selected) {
                selected.push(option.value);
                if (first) {
                    first = false;
                } else {
                    dom_arguments.push({
                        "tagName": "NULL"
                    });
                }
            }
        }

        if (selected.length) {
            selected.forEach((item) => {
                this.add_argument_value(
                    select.id,
                    select.name,
                    item,
                );
            });
        } else {
            this.add_argument_value(
                select.id,
                select.name,
                "",
            );
        }

        return dom_arguments;
    }

    /*
    This method adds an arguments value in the request data.
    */
    add_argument_value(id, name, value) {
        let arguments_ = this.arguments;
        let argument = arguments_[name];

        if (argument !== undefined) {
            if (!Array.isArray(argument["value"])) {
                argument["value"] = [argument["value"]];
            }

            if (value) {
                argument["value"].push(value);
            }
        } else {
            argument = arguments_[name] = {
                "value": value,
                "position": this.script_container.innerHTML.indexOf(
                    `id="${id}"`)
            };

            for (let argument_ of script.script.arguments) {
                if (argument_.name !== name) {
                    continue;
                }

                argument["input"] = (argument_.input === true) ? true :
                    false;
                break;
            }
        }

        this.get_argument_value();
    }

    /*
    This method returns 'light' when theme is light.
    */
    get_theme() {
        if (localStorage.getItem('theme') === "light" || window.matchMedia(
                "(prefers-color-scheme: light)").matches) {
            return 'light';
        }
    }

    /*
    This method redirects to referrer or to "/web/".
    */
    redirect() {
        let referrer = document.referrer;
        window.location = (referrer && referrer.startsWith(window.location
                .origin) && !referrer.endsWith("/web/auth/")) ? referrer :
            window.location = new URL(subpath + "web/", window.location);
    }

    /*
    This method adds the error message when HTTP error is raised.
    */
    http_error(status, message = null) {
        this.error_container.innerText = "HTTP ERROR " + status;

        if (message) {
            this.error_container.innerText += ": " + message
        }

        this.error_container.innerText += ". \nYou can report a bug ";

        let class_link = this.get_theme();
        let link = document.createElement("a");

        if (class_link) {
            link.classList.add(class_link);
        }

        link.href = subpath + "error_pages/Report/new/" + status;
        link.innerText = "on the local report page";
        this.error_container.appendChild(link);

        this.script_end();
    }

    /*
    This method sends the POST request to start script execution.
    */
    send_requests(json, first = true) {
        let xhttp;
        this.xhttp = xhttp = new XMLHttpRequest();

        xhttp.onreadystatechange = () => {
            let status = xhttp.status;

            if (xhttp.readyState === 4) {
                if (status === 200) {
                    this.response_manager(JSON.parse(xhttp
                        .responseText));
                } else if (status === 302 && script_name === "/auth/") {
                    this.redirect();
                } else if (status === 500) {
                    this.http_error(
                        status,
                        "\x49\x6e\x74\x65\x72\x6e\x61\x6c\x20" +
                        "\x53\x65\x72\x76\x65\x72\x20\x45\x72" +
                        "\x72\x6f\x72"
                    );
                } else if (status === 403) {
                    this.http_error(status, "Forbidden");
                } else {
                    this.http_error(status);
                }
            }
        }

        let url = subpath + (
            script_name[0] === "/" ? script_name : "/api/scripts/" +
            script_name
        );

        xhttp.open("POST", url, true);
        xhttp.setRequestHeader('Content-Type', 'application/json');
        xhttp.send(JSON.stringify(json));
        this.start = Date.now();

        this.is_running = true;
        this.progress_animation();
    }

    /*
    This method requests the WebScripts server to
    get a new line for "real time output".
    */
    get_new_line(response) {
        this.xhttp.open('GET', subpath + `api/script/get/${response.key}`, true);
        this.xhttp.send();
    }

    /*
    This method resets the variables and calculates the time.
    */
    script_end() {
        let end = this.end = Date.now();
        this.start_button.disabled = false;
        this.is_running = false;
        this.full_output = "";
        this.full_error = "";

        let diff_seconds = Math.round((end.valueOf() - this.start
        .valueOf()) /
            1000);
        let minutes = Math.round(diff_seconds / 60);
        let seconds = diff_seconds - minutes * 60;

        if (minutes < 10) {
            minutes = `0${minutes}`;
        }
        if (seconds < 10) {
            seconds = `0${seconds}`;
        }

        this.time = minutes + ":" + seconds;
        this.first_ouput = true;
    }

    /*
    This method prints a new line and send
    the new request to get a new line.
    */
    real_time_handler(response) {
        if (!response.code) {
            response.code = "Running...";
        }

        if (!response.error) {
            response.error = "Running...";
        }

        let output_builder = new OutputBuilder(
            response,
            false,
            "Running...",
            this.first_ouput,
            false,
            null,
            null,
            this.arguments,
        );

        if (output_builder.build()) {
            this.first_ouput = false;
        };
        this.get_new_line(response);

        return [response.stdout, response.stderr];
    }

    /*
    This method detects the type of response and
    uses the good behavior for this type of response.
    */
    response_manager(response) {
        let output, error;

        if (response.csrf) {
            this.csrf.value = response.csrf;
        }

        if (response.key) {
            [output, error] = this.real_time_handler(response);
            this.full_output += output;
            this.full_error += error;
            return;
        }

        this.script_end();

        let output_builder = new OutputBuilder(
            response,
            true,
            this.time,
            false,
            true,
            this.full_output,
            this.full_error,
            this.arguments,
        );

        output_builder.build();

        document.getElementById('code').id =
        `last_code_${execution_number}`;
        document.getElementById('last_output').id =
            `last_output_${execution_number}`;
        document.getElementById('console').id =
            `console_${execution_number}`;
    }
}

/*
This class implements functions to add a script execution in the web page.
*/
class OutputBuilder {
    constructor(output, add_history_ = true, time = null, make_new_output =
        true, update = false, full_output = null, full_error = null,
        user_inputs = {}) {
        this.output = output;
        this.add_history_ = add_history_;
        this.time = time;
        this.make_new_output = make_new_output;
        this.update = update;
        this.full_output = full_output;
        this.full_error = full_error;

        this.console_div = document.getElementById("script_outputs");
        this.content_type = output["Content-Type"];
        this.stderr_content_type = "text/plain";
        this.text = "";
        this.html = "";
        this.code;
        this.new_output;

        this.user_inputs = user_inputs;

        this.error_string = this.clean_string(output.stderr);
        this.output_string = this.clean_string(output.stdout);
    }

    /*
    This function deletes whitespace characters on
    the start and the end of the string.
    */
    clean_string(string) {
        return string.replace(/^\s+|\s+$/g, '');
    };

    /*
    This function creates the "code" element and
    add the script execution status.
    */
    code_builder(output, time) {
        let code = document.createElement("code");
        code.id = "code";
        code.classList.add("code");

        code.innerText =
            `>>> ${script_name}    ExitCode: ${output.code}    ` +
            `Error: ${output.error}`;

        if (time) {
            code.innerText += `    ExecutionTime: ${time}`;
        }

        return code;
    }

    /*
    This function creates containers
    for text and HTML content.
    */
    new(code) {
        let new_output = document.createElement("div");
        let console_ = document.createElement("pre");

        new_output.id = "last_output";

        console_.id = "console";
        console_.classList.add("console");

        console_.appendChild(code);
        new_output.appendChild(console_);

        this.make_new_output = true;

        return new_output;
    }

    /*
    This function unescapes HTML special characters.
    */
    unescape = str => str.replace(/&lt;/g, '<').replace(/&gt;/g, '>')
        .replace(/&#x27;/g, "'").replace(/&quot;/g, '"').replace(/&amp;/g, '&');

    /*
    This function escapes HTML special characters.
    */
    escape = str => str.replace(/&/g, '&amp;').replace(/</g, '&lt;')
        .replace(/>/g, '&gt;').replace(/'/g, "&#x27;").replace(/"/g, '&quot;');

    /*
    This function replaces CRLF by universal new line.
    */
    universal_new_line = str => str.replace(/\r\n/g, "\n");

    /*
    This is the main function to put the script
    content in the web interface.
    */
    build() {
        this.get_output_container();
        this.update_status();
        this.add_history();
        this.set_stderr_content_type();

        if ((this.full_output + this.full_error + this.output_string + this
                .error_string).length === 0 && this.add_history_) {
            this.error_string = this.output.stderr =
                "WebScripts warning: There is no output or " +
                "error for this execution.\n";
            this.stderr_content_type = "text/plain";
        }

        this.add_stderr_content();
        this.build_content();
        this.add_content();
        this.add_to_download();
        this.theme();

        return true;
    }

    /*
    This function builds a new container
    or use the last builded container.
    */
    get_output_container() {
        if (this.make_new_output) {
            this.code = this.code_builder(this.output, this.time);
            this.new_output = this.new(this.code);
        } else {
            this.code = document.getElementById("code") || this
                .code_builder(this.output, this.time);
            this.new_output = document.getElementById("last_output") || this
                .new(this.code);
        }
    }

    /*
    This function updates the status at the
    end of the script execution.
    */
    update_status() {
        if (this.update) {
            this.code.innerText = this.code.innerText.replace('Running...',
                this.output.code).replace('Running...', this.output
                .error).replace('Running...', this.time);
        }
    }

    /*
    This function adds a new script content in the history.
    */
    add_history() {
        if (this.add_history_) {
            let history = new History();
            history.add(this);
        }
    }

    /*
    This function sets the stderr
    content type from the server response.
    */
    set_stderr_content_type() {
        if (this.output.hasOwnProperty("Stderr-Content-Type")) {
            this.stderr_content_type = this.output["Stderr-Content-Type"];
        }
    }

    /*
    This function adds the stderr to the string content.
    */
    add_stderr_content() {
        if (this.error_string.length !== 0) {
            if (this.stderr_content_type.includes("text/html")) {
                this.html += this.anti_XSS(this.output.stderr);
            } else if (this.stderr_content_type.includes("text/csv")) {
                this.html += csv_to_html(this.output.stderr);
            } else if (this.stderr_content_type.includes("text/json")) {
                this.text += JSON.stringify(JSON.parse(this.output.stderr),
                    null, "    ");
            } else {
                this.text += `\n${this.output.stderr}`;
            }
        }
    }

    /*
    This function sets the download parameters
    and adds the stdout to the string content.
    */
    build_content() {
        let html_content = () => {
            download_separator = "\n<br>\n";
            download_extension = ".html";
            download_type = "html";
        }

        let text_content = () => {
            download_extension = ".txt";
            download_separator = "\n";
            download_type = "plain";
        }

        let add_text_output = (text) => {
            this.text = this.make_new_output ? `\n${text}${this.text}` :
                `${this.text}${text}`;;
        }

        if (this.content_type.includes("text/html")) {
            html_content();
            this.html = this.anti_XSS(this.output.stdout) + this.html;
        } else if (this.content_type.includes("text/csv")) {
            html_content();
            this.html = ParserCSV.prototype.csv_to_html(null, this.output
                .stdout, '"', ',', '\r\n').outerHTML;
        } else if (this.content_type.includes("text/json")) {
            text_content();
            add_text_output(JSON.stringify(JSON.parse(this.output.stdout),
                null, "    "));
        } else {
            text_content();
            add_text_output(this.output.stdout);
        }
    }

    /*
    This function cleans and adds the string content to the container.
    */
    add_content() {
        this.code.innerText += this.universal_new_line(this.unescape(this
            .text));
        this.new_output.innerHTML += this.html;
        this.console_div.appendChild(this.new_output);
        ShortTable.prototype.add_listeners();
    }

    /*
    This function adds the string content to the download content.
    */
    add_to_download() {
        download_text += `${this.text}\n${this.html}${download_separator}`;
    }

    /*
    This function changes the color theme of the child elements of the
    container.
    */
    theme() {
        if (localStorage.getItem('theme') === "light" || (localStorage
                .getItem('theme') === null && !dark_theme)) {
            Theme.prototype.change_elements('light', this.new_output);
        }
        /* else if (localStorage.getItem('theme') === null) {
            change_theme(
                class_name = 'default_theme',
                element = this.new_output,
            );
        }*/
    }

    /*
    This function protects the browser against the XSS
    vulnerabilities based on the user inputs only.
    */
    anti_XSS(content) {
        for (let value of Object.values(this.user_inputs)) {
            value = value.value;
            if (value.constructor.name !== "String" && value.constructor.name !== "Array") continue;
            if (value.constructor.name !== "Array") value = [value];
            for (let v of value) {
                let secure_value = this.escape(v);
                if (v !== secure_value) {
                    content = content.replaceAll(v, secure_value);
                }
            }
        }

        return content;
    }
}

/*
This function implements this history actions.
*/
class History {
    constructor() {
        this.container = document.getElementById("webscripts_history");
    }

    /*
    This function deletes the history content.
    */
    clear() {
        execution_number = 0;
        this.container.innerText = "";
    }

    /*
    This function display or hide history.
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
    This function adds a script execution in history.
    */
    add(output_builder) {
        let button = document.createElement("button");

        output_builder.add_history_ = false;
        button.onclick = () => {
            output_builder.get_output_container();
            output_builder.add_content();
            output_builder.add_to_download();
            output_builder.theme();
        }

        button.innerText = "Execution " + execution_number;
        execution_number++;
        this.container.appendChild(button);

        if (localStorage.getItem('theme') === "light") {
            button.classList.toggle("light");
        } else if (localStorage.getItem('theme') === null) {
            button.classList.toggle("default_theme");
        }
    }
}

/*
This class parses a CSV file.
*/
class ParserCSV {
    constructor(quote = '"', value_delimiter = ',', line_delimiter = "\n") {
        let value_regex_string =
            `(${quote}([^${quote}]|${quote}${quote})*${quote}|` +
            `[^${quote}${value_delimiter}${line_delimiter}]*)`;
        this.regex_line = new RegExp('((' + value_regex_string +
            value_delimiter + ')*' + value_regex_string + '+|(' +
            value_regex_string + value_delimiter + ')+' +
            value_regex_string + ')', "gm");
        this.regex_value = new RegExp(
            `((${quote}([^${quote}]|${quote}${quote})*${quote}|[^${quote}` +
            `${value_delimiter}${line_delimiter}]+)|${value_delimiter})`,
            "gm");
    }

    /*
    This function parses CSV and build an HTML output.
    */
    csv_to_html(headers, data, ...args) {
        let csv_parser = new ParserCSV(...args);
        let arrays = csv_parser.parse(data);

        headers = headers || arrays.shift();

        let table = document.createElement("table");
        let thead = table.createTHead();
        let tbody = table.createTBody();

        let line = document.createElement("tr");
        thead.appendChild(line);

        for (let header of headers) {
            let column = document.createElement("th");
            line.appendChild(column);
            column.innerText = header;
        }

        for (let line_values of arrays) {
            line = document.createElement("tr");
            tbody.appendChild(line);
            for (let column_value of line_values) {
                let column = document.createElement("td");
                line.appendChild(column);
                column.innerText = column_value;
            }
        }

        return table;
    }

    /*
    This function parses a CSV file.
    */
    parse(data) {
        let lines = data.matchAll(this.regex_line);

        let arrays = [];
        let array = [];

        for (let line of lines) {
            let text_line = line[0];
            if (text_line) {
                this.parse_line(text_line, array);
                arrays.push(array);
                array = [];
            }
        }

        if (array.length) {
            arrays.push(array);
        }

        return arrays;
    }

    /*
    This function parses a CSV line.
    */
    parse_line(line, array) {
        let values = line.matchAll(this.regex_value);
        let not_empty = false;

        for (let value of values) {
            let data = value[0];

            if (data === ",") {
                if (!not_empty) {
                    array.push("");
                }
                not_empty = false;
                continue;
            }

            not_empty = true;
            this.parse_value(data, array);
        }

        if (!not_empty) {
            array.push("");
        }
    }

    /*
    This function parses a CSV value.
    */
    parse_value(data, array) {
        if (data[0] === '"') {
            array.push(data.substring(1, data.length - 1).replace('""',
                '"'));
        } else {
            array.push(data);
        }
    }
}

/*
This class adds an event listener on each
table header to shorts tables by values.
*/
class ShortTable {

    /*
    This function returns the column value.
    */
    get_value(line, id) {
        return line.children[id].innerText || line.children[id].textContent;
    }

    /*
    This function compares two values.
    */
    compare(value1, value2) {
        if (value1 !== '' && value2 !== '' && !isNaN(value1) && !isNaN(
                value2)) {
            return value1 - value2;
        } else {
            return value1.toString().localeCompare(value2)
        }
    }

    /*
    This function generates the event listener callback.
    */
    get_callback(id, ascendant) {
        return function short_callback(line1, line2) {
            if (!ascendant) {
                let temp = line1;
                line1 = line2;
                line2 = temp;
            }

            return ShortTable.prototype.compare(ShortTable.prototype
                .get_value(line1, id), ShortTable.prototype
                .get_value(line2, id));
        };
    }

    /*
    This function shorts the table.
    */
    event() {
        let table = this.closest('table');
        let id = Array.from(this.parentNode.children).indexOf(this);

        Array.from(table.querySelectorAll('tr:nth-child(n+2)'))
            .sort(ShortTable.prototype.get_callback(id, window.ascendant = !
                window.ascendant))
            .forEach(line => table.appendChild(line));
    }

    /*
    This function adds listeners on each table headers.
    */
    add_listeners() {

        document.querySelectorAll('th').forEach((header) => {
            if (!header.have_short_event) {
                header.addEventListener('click', ShortTable
                    .prototype.event.bind(header));
                header.innerText = "⋁ " + header.innerText;
                header.have_short_event = true;
                header.style.cursor = "pointer";
                setTimeout(() => {
                    let search = new TableSearch(header
                        .closest('table'))
                }, 500);
            }
        });
    }
}

/*
This class implements a tool to search lines in HTML table.
*/
class TableSearch {
    constructor(table) {
        if (table.have_search) {
            return;
        }

        let is_light = document.getElementsByClassName('light').length;

        let input, parent;
        this.table = table;
        input = this.input = document.createElement('input');

        parent = this.parent = table.parentNode;
        input.type = "text";
        input.classList.add("webscripts_search_table");
        input.onchange = this.search.bind(this);
        input.placeholder = "🔍  Search/Filter table values";
        table.have_search = true;

        this.selected_column = null;
        parent.insertBefore(input, table);

        this.headers = table.getElementsByTagName('th');

        if (is_light) input.classList.add('light');

        this.add_selects(is_light);
    }

    /*
    This function adds a select box to headers to filter only on this column.
    */
    add_selects(is_light) {
        let counter = 0;

        for (let header of this.headers) {
            let id = counter;
            let select = document.createElement("span");
            select.innerText = "☐";
            select.classList.add("webscripts_column_select");
            if (is_light) select.classList.add('light');
            select.addEventListener('click', () => {
                this.select_column(id);
            });
            header.appendChild(select);
            header.selected = false;
            header.select = select;

            counter++;
        }
    }

    /*
    This function unselects columns.
    */
    unselect_column() {
        this.selected_column = null;

        for (let header of this.headers) {
            header.select.innerText = "☐";
            header.select.classList.remove("selected");
            header.select.classList.remove("unselected");
        }

        this.search();
    }

    /*
    This function selects columns.
    */
    select_column(id) {
        if (this.selected_column !== null) {
            this.unselect_column();
            return;
        }

        this.selected_column = id;
        let counter = 0;

        for (let header of this.headers) {
            if (counter === id) {
                header.select.innerText = "☑";
                header.select.classList.add("selected");
            } else {
                header.select.innerText = "☒";
                header.select.classList.add("unselected");
            }

            counter++;
        }

        this.search();
    }

    /*
    This function searchs in table.
    */
    search() {
        let filter = this.input.value.toUpperCase();
        let lines = this.table.getElementsByTagName("tr");

        for (let line of lines) {
            let columns = line.getElementsByTagName("td");

            if (!columns.length) {
                continue;
            }

            if (this.selected_column !== null) {
                columns = [columns[this.selected_column]];
            }

            let is_matching = false;
            for (let column of columns) {
                let value = column.textContent || column.innerText;

                if (value.toUpperCase().indexOf(filter) > -1) {
                    is_matching = true;
                }
            }

            if (is_matching) {
                line.style.display = "";
            } else {
                line.style.display = "none";
            }
        }
    }
}
