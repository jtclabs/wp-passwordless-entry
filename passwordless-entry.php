<?php

/*
Plugin Name: Passwordless Entry
Plugin URI: https://jtclabs.com/wp-passwordless-entry
Description: This plugin allows users to log into the site without a password, by sending a one-time authentication link to the user's registered email address.
Version: 1.0
Author: JohnoTheCoder
Author URI: https://johnothecoder.uk
License: GPL2
*/

// All constants prefixed with PLE (PasswordLess Entry)

// Ability to disable the functionality without disabling the plugin, if the administrator wants to
if (!defined('PLE_ENABLED')) {
    define('PLE_ENABLED', true);
}

// How long should a passwordless entry key last (in minutes)
if (!defined('PLE_EXPIRATION_MINUTES')) {
    define('PLE_EXPIRATION_MINUTES', 5);
}

// How long should the PLE key be (default 64 characters)
if (!defined('PLE_KEY_LENGTH')) {
    define('PLE_KEY_LENGTH', 64);
}

// What GET parameter are we going to use to define that we're trying to use the PLE system
if (!defined('PLE_CONTROLLER_KEY')) {
    define('PLE_CONTROLLER_KEY', 'ple');
}

// What GET parameter are we going to use for the passwordless entry key
if (!defined('PLE_ACCESS_KEY_PARAMETER')) {
    define('PLE_ACCESS_KEY_PARAMETER', 'ple_key');
}

// What POST/REQUEST parameter will we check for the email to which a PLEK should be sent
if (!defined('PLE_EMAIL_KEY')) {
    define('PLE_EMAIL_KEY', 'ple_email');
}

// When we store the PLE information in the options table, how should we prefix our options (default ple_x)
if (!defined('PLE_OPTIONS_PREFIX')) {
    define('PLE_OPTIONS_PREFIX', 'ple_');
}

// Where will we store the PLEKs specifically, default (ple_key_x)
if (!defined('PLE_OPTIONS_KEY_PREFIX')) {
    define('PLE_OPTIONS_KEY_PREFIX', PLE_OPTIONS_PREFIX . 'key_');
}

// What user meta key will we use to store the latest PLEK for this user
if (!defined('PLE_USER_META_KEY')) {
    define('PLE_USER_META_KEY', '_ple_latest_key');
}

/**
 * We are only going to register the controller action and the shortcode if PLE is enabled.
 * This means that the administrator of the website can disable the functionality if they wish, by defining
 * PLE_ENABLED as false in the wp-config.php
 */
if (PLE_ENABLED === true){
    add_action('init', 'ple_controller');
    add_shortcode('ple', 'ple_shortcode');
}

/**
 *
 * Render the relevant HTML on the page
 *
 */
function ple_shortcode(){

    // We are requesting a Passwordless Entry Key (relevant key set in POST, and it is an email address)
    if (isset($_REQUEST[PLE_EMAIL_KEY]) && filter_var($_REQUEST[PLE_EMAIL_KEY], FILTER_VALIDATE_EMAIL)) {
        ple_request_entry($_REQUEST[PLE_EMAIL_KEY]);
        return ple_view('requested');
    }

    if (

        // The relevant access key parameter is set in the URL
        isset($_GET[PLE_ACCESS_KEY_PARAMETER])

        // The access key parameter is not empty
        && !empty($_GET[PLE_ACCESS_KEY_PARAMETER])

        // We have a verifiable passwordless entry key
        && ple_verify($_GET[PLE_ACCESS_KEY_PARAMETER]) === true

        // We have successfully authenticated against that PLE key
        && ple_authenticate($_GET[PLE_ACCESS_KEY_PARAMETER]) === true

    ) {

        // We have authenticated this user, let's tell them
        return ple_view('success');

    }

    // Show the PLE request screen
    return ple_view('request');

}

/**
 * Controls and routes requested for passwordless entry
 */
function ple_controller() {

    // If we don't have a controller key, or the controller key is not set to TRUE, or the user is already logged in
    if (!isset($_REQUEST[PLE_CONTROLLER_KEY]) || $_REQUEST[PLE_CONTROLLER_KEY] != true || is_user_logged_in()) {
        return;
    }

    // We are requesting a PLEK
    if (isset($_REQUEST[PLE_EMAIL_KEY]) && filter_var($_REQUEST[PLE_EMAIL_KEY], FILTER_VALIDATE_EMAIL)) {
        ple_request_entry($_REQUEST[PLE_EMAIL_KEY]);
        die(ple_view('requested'));
    }

    if (

        // We have the access key parameter
        isset($_GET[PLE_ACCESS_KEY_PARAMETER])

        // The access key parameter is not empty
        && !empty($_GET[PLE_ACCESS_KEY_PARAMETER])

        // The access key is verified
        && ple_verify($_GET[PLE_ACCESS_KEY_PARAMETER]) === true

        // We have successfully authenticated
        && ple_authenticate($_GET[PLE_ACCESS_KEY_PARAMETER]) === true

    ) {
        // We have authenticated this user, let's send them back to the site, where they should be authenticated
        header('Location:' . get_bloginfo('url'));
    }

    // Show the PLE request screen
    die(ple_view('request'));
}

/**
 *
 * Verify and create the entry key
 *
 * @param $email
 *
 * @return bool
 */
function ple_request_entry($email) {

    // Try to locate the user by the email address
    $user = get_user_by('email', $email);

    // If we cannot find a user, we'll return FALSE
    if ($user === false) {
        return false;
    }

    // Create the entry key and return TRUE
    ple_create_entry_key($user->ID, $user->user_email);
    return true;

}

/**
 *
 * Create an entry key for this
 *
 * @param $userId
 * @param $email
 *
 * @return bool
 */
function ple_create_entry_key($userId, $email) {

    // Generate a key using WordPress password generation, to the length specified by the constant
    $key = wp_generate_password(PLE_KEY_LENGTH, false, false);

    // Calculate when this key should expire
    $expiration = time() + (PLE_EXPIRATION_MINUTES * 60);

    // Generate the URL to which the user will be directed
    $url = get_site_url() . '?' . PLE_ACCESS_KEY_PARAMETER . '=' . $key . '&' . PLE_CONTROLLER_KEY . '=true';

    // Get the user object, as we'll want some information for the email
    $user = get_user_by('id', $userId);

    // This is the object that's going to be stored in wp_options
    $details = (object)[
        'user_id' => $userId,
        'user_email' => $email,
        'key' => $key,
        'expiration' => $expiration,
        'provided_url' => $url
    ];

    // If we find an existing key for this user, we're going to immediately decommission it
    // this serves a couple of purposes, firstly it means that we don't have any floating keys around, but also it means
    // in the event of someone spamming lots of keys for the same user account, we will only store one - removing their
    // ability to completely kill the options table
    $existingKey = get_user_meta($userId, PLE_USER_META_KEY);
    if (!empty($existingKey)) {
        delete_option(PLE_OPTIONS_KEY_PREFIX . $existingKey[0]);
    }

    // Add the details of the key to the options table
    update_option(PLE_OPTIONS_KEY_PREFIX . $key, $details);

    // Store the key in the user_meta
    update_user_meta($userId, PLE_USER_META_KEY, $key);

    // Send the email to the user with the relevant information
    wp_mail(
        $email,
        'Your Passwordless Entry URL',
        ple_view(
            'email',
            [
                'NAME' => $user->display_name,
                'LINK' => $url,
                'MINUTES' => PLE_EXPIRATION_MINUTES
            ]
        )
    );

    // Once we have finished this process, we'll return TRUE
    return true;

}

/**
 *
 * Verify whether or not this key can be utilised for password-less authentication
 *
 * @param $key
 *
 * @return bool
 */
function ple_verify($key) {

    // Retrieve the options from the database
    $option = get_option(PLE_OPTIONS_KEY_PREFIX . $key);

    // Key is not set
    if (empty($option)) {
        return false;
    }

    // Key is expired, so we're going to reject it
    if($option->expiration < time()) {
        return false;
    }

    // Only one key at a time can be used - a new key has been issued (this should never happen, but safety check nonetheless)
    if (get_user_meta($option->user_id, PLE_USER_META_KEY)[0] != $key){
        return false;
    }

    return true;

}

/**
 *
 * Authenticate the user, using the provided (verified) key
 *
 * @param $key
 *
 * @return bool
 */
function ple_authenticate($key){
    $option = get_option(PLE_OPTIONS_KEY_PREFIX . $key);
    wp_set_auth_cookie($option->user_id);
    delete_option(PLE_OPTIONS_KEY_PREFIX . $key);
    return true;
}

/**
 *
 * Return HTML with replacements
 *
 * @param      $template
 * @param null $additionalReplacements
 *
 * @return false|string|string[]
 */
function ple_view($template, $additionalReplacements = null) {
    $html = file_get_contents(__DIR__ . '/templates/' . $template . '.html');
    $replacements = [
        'SITE_NAME' => get_bloginfo('name'),
        'EMAIL_KEY' => PLE_EMAIL_KEY,
        'SITE_URL' => get_bloginfo('url')
    ];
    foreach($additionalReplacements as $find => $replace){
        if (isset($replacemenets[$find])) {
            continue;
        }
        $replacements[$find] = $replace;
    }
    foreach($replacements as $find => $replace){
        $find = '{{' . $find . '}}';
        $html = str_replace($find, $replace, $html);
    }
    return $html;
}