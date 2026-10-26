<?php

function parse_message(string $encoded): mixed
{
    return json_decode($encoded, true, flags: JSON_THROW_ON_ERROR);
}
