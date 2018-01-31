<?php
/**
 * @package		Password policy
 * @subpackage	plg_user_passwordpolicy
 *
 * @author		Helios Ciancio <info@eshiol.it>
 * @link		http://www.eshiol.it
 * @copyright	Copyright (C) 2018 Helios Ciancio. All Rights Reserved
 * @license		http://www.gnu.org/licenses/gpl-3.0.html GNU/GPL v3
 * Password Policy for Joomla! is free software. This version may have been
 * modified pursuant to the GNU General Public License, and as distributed
 * it includes or is derivative of works licensed under the GNU General Public
 * License or other free or open source software licenses.
 */

defined('JPATH_PLATFORM') or die;

use Joomla\Registry\Registry;

/**
 * JFormRule for plg_user_passwordpolicy
 *
 * @since  3.8.2
 */
class JFormRulePasswordage extends JFormRule
{
	/**
	 * Method to test if two fields have a value in order to use only one field.
	 * To use this rule, the form
	 * XML needs a validate attribute of loginuniquefield and a field attribute
	 * that is equal to the field to test against.
	 *
	 * @param   SimpleXMLElement  $element  The SimpleXMLElement object representing the `<field>` tag for the form field object.
	 * @param   mixed             $value    The form field value to validate.
	 * @param   string            $group    The field name group control value. This acts as an array container for the field.
	 *                                      For example if the field has name="foo" and the group value is set to "bar" then the
	 *                                      full field name would end up being "bar[foo]".
	 * @param   Registry          $input    An optional Registry object with the entire data set to validate against the entire form.
	 * @param   JForm             $form     The form object for which the field is being tested.
	 *
	 * @return  boolean  True if the value is valid, false otherwise.
	 *
	 * @since   3.8.2
	 */
	public function test(SimpleXMLElement $element, $value, $group = null, Registry $input = null, JForm $form = null)
	{
	    $field = (string) $element['field'];

	    // Check that a validation field is set.
	    if (!$field)
	    {
	        throw new \UnexpectedValueException(sprintf('$field empty in %s::test', get_class($this)));
	    }

	    if (is_null($form))
	    {
	        throw new \InvalidArgumentException(sprintf('The value for $form must not be null in %s', get_class($this)));
	    }

	    if (is_null($input))
	    {
	        throw new \InvalidArgumentException(sprintf('The value for $input must not be null in %s', get_class($this)));
	    }

	    if ($value == 0)
	    {
	        $test = 1;
	    }
	    elseif (isset($group) && $group !== '')
	    {
	        $test = $input->get($group . '.' . $field);
	    }
	    else
	    {
	        $test = $input->get($field);
	    }

	    return $value < $test;
	}
}
