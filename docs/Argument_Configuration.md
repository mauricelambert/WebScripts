# Argument configuration

## Structure

JSON configuration:
```json
{
    "config_delete_user": {
        "args": "config_delete_user_args"
    },

    "config_delete_user_args": {
        "id": "arg_id"
    },

    "arg_id": {
        "list": false,
        "input": false,
        "example": "55",
        "is_advanced": true,
        "html_type": "number",
        "default_value": null,
        "predefined_values": null,
        "javascript_section": "javascript_id",
        "description": "User ID (must be unique)"
    },

    "javascript_id": {
        "step": "0.002"
    }
}
```

INI configuration:
```ini
[config_auth]
args=auth_args                                                                                 # The arguments are defined in section named "auth_args"

[auth_args]
--username=arg_username                                                                        # Add a configuration section ("arg_username") for the argument named "--username"

[arg_username]
html_type=text                                                                                 # Define the HTML input type for this argument
description=Your username (to log in)                                                          # Short description to help users
default_value                                                                                  # Add default value
predefined_values                                                                              # To build a list box (<select> in HTML) with a list of values
example=user                                                                                   # Add example (placeholder in HTML)
list=false                                                                                     # Only one username, if true the user can add usernames (as much as the user wants)
input=false                                                                                    # To send the argument in STDIN (interactive mode)
javascript_section=javascript_username                                                         # Define the Javascript section

[javascript_username]
title=Your username (to log in)                                                                # Add a title on the input (javascript attribute is "title")
```

1. In the script section, add the `args` configuration to define the name of the *arguments section*
2. Create your *arguments section*
3. Add all *arguments* by *argument name* for this script (if *argument name* starts with `-`, it will be added in the command line) and set the *section name* of the argument.
4. Create your *argument section* and add your configurations

## Configurations

 - `html_type`: the HTML type is the *input type* [define here](https://www.w3schools.com/html/html_form_input_types.asp) (not required, default is `text`)
 - `description`: a short description to help users (not required)
 - `default_value`: a default value for the argument (not required)
 - `predefined_values`: to add a `select` object (a list box) for a choice between some values (not required, if define the `html_type` is not used)
 - `example`: add an example for the value (not required)
 - `list`: if defined as `true` the user can add values (as much as the user wants) (not required, default is `false`)
 - `input`: if defined as `true` value(s) will be send in *stdin* (user input, interactive mode) (not required, default is `false`)
 - `is_advanced`: if set as `true` the html input will be hidden by default, users can click the `show advanced arguments` button to print hidden inputs (not required, default is `false`)
 - `javascript_section`: set the section name to define javascript attributes and values
