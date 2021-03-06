<?php

require __DIR__ . '/vendor/autoload.php';

use mindplay\blowfish\BlowfishService;

test(
    'Entropy functions work as expected',
    function () {
        $service = new BlowfishService();

        $entropy = invoke($service, 'getEntropy', array(10));

        ok(strlen($entropy) === 10, 'returns 10 bytes of entropy');

        $entropy = invoke($service, 'getEntropy', array(100));

        ok(strlen($entropy) === 100, 'returns 100 bytes of entropy');
    }
);

test(
    'Can hash and check passwords',
    function () {
        foreach (array(4,10) as $cost) {
            $service = new BlowfishService($cost);

            foreach (array('x', 'p@s$w0Rd', 'KytmCwqjb6wYPGgEHZ55DRfDanNVWwxnmMMnzCRu72ghQ89S') as $password) {
                $hash = $service->hash($password);

                ok($service->check($password, $hash), 'password verified (with cost ' . $cost . ')', $password);
                ok($service->check($password . '-', $hash) === false, 'invalid password rejected (with cost ' . $cost . ')', $password);
                ok($service->check($password, $hash . '-') === false, 'invalid hash rejected (with cost ' . $cost . ')', $password);
            }
        }
    }
);

exit(status());

// https://gist.github.com/mindplay-dk/4260582

/**
 * @param string   $name     test description
 * @param callable $function test implementation
 */
function test($name, $function)
{
    echo "\n=== $name ===\n\n";

    try {
        call_user_func($function);
    } catch (Exception $e) {
        ok(false, "UNEXPECTED EXCEPTION", $e);
    }
}

/**
 * @param bool   $result result of assertion
 * @param string $why    description of assertion
 * @param mixed  $value  optional value (displays on failure)
 */
function ok($result, $why = null, $value = null)
{
    if ($result === true) {
        echo "- PASS: " . ($why === null ? 'OK' : $why) . ($value === null ? '' : ' (' . format($value) . ')') . "\n";
    } else {
        echo "# FAIL: " . ($why === null ? 'ERROR' : $why) . ($value === null ? '' : ' - ' . format($value,
                    true)) . "\n";
        status(false);
    }
}

/**
 * @param mixed  $value    value
 * @param mixed  $expected expected value
 * @param string $why      description of assertion
 */
function eq($value, $expected, $why = null)
{
    $result = $value === $expected;

    $info = $result
        ? format($value)
        : "expected: " . format($expected, true) . ", got: " . format($value, true);

    ok($result, ($why === null ? $info : "$why ($info)"));
}

/**
 * @param mixed $value
 * @param bool  $verbose
 *
 * @return string
 */
function format($value, $verbose = false)
{
    if ($value instanceof Exception) {
        return get_class($value)
        . ($verbose ? ": \"" . $value->getMessage() . "\"" : '');
    }

    if (!$verbose && is_array($value)) {
        return 'array[' . count($value) . ']';
    }

    if (is_bool($value)) {
        return $value ? 'TRUE' : 'FALSE';
    }

    if (is_object($value) && !$verbose) {
        return get_class($value);
    }

    return print_r($value, true);
}

/**
 * @param bool|null $status test status
 *
 * @return int number of failures
 */
function status($status = null)
{
    static $failures = 0;

    if ($status === false) {
        $failures += 1;
    }

    return $failures;
}

/**
 * Invoke a protected or private method (by means of reflection)
 *
 * @param object $object      the object on which to invoke a method
 * @param string $method_name the name of the method
 * @param array  $arguments   arguments to pass to the function
 *
 * @return mixed the return value from the function call
 */
function invoke($object, $method_name, $arguments = array())
{
    $class = new ReflectionClass(get_class($object));

    $method = $class->getMethod($method_name);

    $method->setAccessible(true);

    return $method->invokeArgs($object, $arguments);
}
