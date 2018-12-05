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

// no direct access
defined('_JEXEC') or die('Restricted access.');

jimport('joomla.plugin.plugin');

class plgUserPasswordpolicy extends JPlugin
{
	/**
	 * Application object
	 *
	 * @var	JApplicationCms
	 * @since  3.8.4
	 */
	protected $app;

	/**
	 * Load the language file on instantiation.
	 *
	 * @var	boolean
	 */
	protected $autoloadLanguage = true;

	/**
	 * Constructor
	 *
	 * @param  object  $subject  The object to observe
	 * @param  array   $config   An array that holds the plugin configuration
	 */
	function __construct(&$subject, $config)
	{
		parent::__construct($subject, $config);

		if ($this->params->get('debug') || defined('JDEBUG') && JDEBUG)
		{
			JLog::addLogger(array('text_file' => $this->params->get('log', 'eshiol.log.php'), 'extension' => 'plg_user_passwordpolicy_file'), JLog::ALL, array('plg_user_passwordpolicy'));
		}
		JLog::addLogger(array('logger' => (null !== $this->params->get('logger')) ? $this->params->get('logger') : 'messagequeue', 'extension' => 'plg_user_passwordpolicy'), JLOG::ALL & ~JLOG::DEBUG, array('plg_user_passwordpolicy'));
		if ($this->params->get('phpconsole') && class_exists('JLogLoggerPhpconsole'))
		{
			JLog::addLogger(array('logger' => 'phpconsole', 'extension' => 'plg_user_passwordpolicy_phpconsole'),  JLOG::DEBUG, array('plg_user_passwordpolicy'));
		}
		JLog::add(new JLogEntry(__METHOD__, JLog::DEBUG, 'plg_user_passwordpolicy'));
	}

	/**
	 * This event is triggered whenever a user is successfully logged in.
	 *
	 * @param   array  $options  Array holding options (remember, return, entry_url, action, user - JUser Object, responseType)
	 *
	 * @return  boolean  True on success
	 */
	public function onUserAfterLogin($options)
	{
		JLog::add(new JLogEntry(__METHOD__, JLog::DEBUG, 'plg_user_passwordpolicy'));

		$user	  = $options['user'];
		$userId   = $user->id;
		$db		  = JFactory::getDbo();
		$nullDate = $db->getNullDate();
		$today	= JFactory::getDate();

		$query	= $db->getQuery(true)
			->select(array('profile_key', 'profile_value'))
			->from($db->qn('#__user_profiles'))
			->where($db->qn('user_id') . ' = ' . $userId)
			->where($db->qn('profile_key') . ' LIKE ' . $db->q('passwordpolicy.%'))
			->order('ordering')
			;
		$db->setQuery($query);

		try
		{
			$results = $db->loadRowList();
		}
		catch (RuntimeException $e)
		{
			$this->_subject->setError($e->getMessage());

			return false;
		}

		// Get the password policy data.
		$passwordpolicy = array();
		foreach ($results as $v)
		{
			$k = str_replace('passwordpolicy.', '', $v[0]);
			$passwordpolicy[$k] = json_decode($v[1], true);

			if ($passwordpolicy[$k] === null)
			{
				$passwordpolicy[$k] = $v[1];
			}
		}

		if (isset($passwordpolicy['maximumPasswordAge']) &&  $passwordpolicy['maximumPasswordAge'])
		{
			$passwordpolicy['maximumPasswordAge'] = min($passwordpolicy['maximumPasswordAge'], (int)$this->params->get('maximumPasswordAge'), $passwordpolicy['maximumPasswordAge']);
		}
		else
		{
			$passwordpolicy['maximumPasswordAge'] = (int)$this->params->get('maximumPasswordAge');
		}

		if ($passwordpolicy['maximumPasswordAge'])
		{
			JLog::add(new JLogEntry('maximumPasswordAge: ' . $passwordpolicy['maximumPasswordAge'], JLog::DEBUG, 'plg_user_passwordpolicy'));

			$date = new JDate((isset($passwordpolicy['pwdLastSet']) ? $passwordpolicy['pwdLastSet'] : $user->registerDate) . ' + ' . $passwordpolicy['maximumPasswordAge'] . ' days');

			JLog::add(new JLogEntry('pwdLastSet: ' . (isset($passwordpolicy['pwdLastSet']) ? $passwordpolicy['pwdLastSet'] : $nullDate), JLog::DEBUG, 'plg_user_passwordpolicy'));
			JLog::add(new JLogEntry('registerDate: ' . $user->registerDate, JLog::DEBUG, 'plg_user_passwordpolicy'));
			JLog::add(new JLogEntry('today: ' . $today->toSql(), JLog::DEBUG, 'plg_user_passwordpolicy'));
			JLog::add(new JLogEntry('expitation date: ' . $date->toSql(), JLog::DEBUG, 'plg_user_passwordpolicy'));

			JLog::add(new JLogEntry('passwordExpirationReminder: ' . $this->params->get('passwordExpirationReminder', 1), JLog::DEBUG, 'plg_user_passwordpolicy'));

			if ($date < $today)
			{
				// Update the reset flag
				try
				{
					JLog::add(new JLogEntry('Your password has expired', JLog::DEBUG, 'plg_user_passwordpolicy'));
					$db->setQuery($db->getQuery(true)
						->update($db->qn('#__users'))
						->set($db->qn('requireReset') . ' = 1')
						->where($db->qn('id') . ' = ' . $user->id)
						)->execute();
				}
				catch (RuntimeException $e)
				{
				}
			}
			elseif ($this->params->get('passwordExpirationReminder', 1))
			{
				JLog::add(new JLogEntry('passwordExpirationReminder', JLog::DEBUG, 'plg_user_passwordpolicy'));
				if (($days = $today->diff($date)->format('%a') + 1) == 1)
				{
					JLog::add(new JLogEntry(JText::sprintf('PLG_USER_PASSWORDPOLICY_PASSWORDLLEXPIREIN_1', $days), JLog::WARNING, 'plg_user_passwordpolicy'));
				}
				elseif (in_array($days, array(2, 3, 7, 15, 30)))
				{
					JLog::add(new JLogEntry(JText::sprintf('PLG_USER_PASSWORDPOLICY_PASSWORDLLEXPIREIN', $days), JLog::WARNING, 'plg_user_passwordpolicy'));
				}
			}
		}
		else
		{
			JLog::add(new JLogEntry('Password never expires', JLog::DEBUG, 'plg_user_passwordpolicy'));
		}
		return true;
	}


	/**
	 * Utility method to act on a user after it has been saved.
	 *
	 * This method sends a registration email to new users created in the backend.
	 *
	 * @param   array	$user	 Holds the new user data.
	 * @param   boolean  $isnew	True if a new user is stored.
	 * @param   boolean  $success  True if user was successfully stored in the database.
	 * @param   string   $msg	  Message.
	 *
	 * @return  void
	 */
	public function onUserAfterSave($user, $isnew, $success, $msg)
	{
		JLog::add(new JLogEntry(__METHOD__, JLog::DEBUG, 'plg_user_passwordpolicy'));
		JLog::add(new JLogEntry('user: '.print_r($user, true), JLog::DEBUG, 'plg_user_passwordpolicy'));
		$userId	= JArrayHelper::getValue($user, 'id', 0, 'int');

		if ($userId && $success)
		{
			// Load the profile data from the database.
			$db = JFactory::getDbo();
			$db->setQuery($query = $db->getQuery(true)
				->select(array('profile_key','profile_value'))
				->from($db->qn('#__user_profiles'))
				->where($db->qn('user_id') . ' = ' . $userId)
				->where($db->qn('profile_key') . ' LIKE ' . $db->q('passwordpolicy.%'))
				->order($db->qn('ordering'))
				);
			JLog::add(new JLogEntry($query, JLog::DEBUG, 'plg_user_passwordpolicy'));
			$results = $db->loadRowList();
			JLog::add(new JLogEntry(print_r($results, true), JLog::DEBUG, 'plg_user_passwordpolicy'));
			// Merge the profile data.
			$data_passwordpolicy = array();
			foreach ($results as $v) {
				$k = str_replace('passwordpolicy.', '', $v[0]);
				$data_passwordpolicy[$k] = json_decode($v[1], true);
			}
			JLog::add(new JLogEntry('data_passwordpolicy: '.print_r($data_passwordpolicy, true), JLog::DEBUG, 'plg_user_passwordpolicy'));

			if (isset($user['passwordpolicy']) && (count($user['passwordpolicy'])))
			{
				unset($user['passwordpolicy']['pwdLastSet']);
				foreach ($user['passwordpolicy'] as $k => $v)
				{
					$data_passwordpolicy[$k] = $v;
				}
			}

			if (isset($user['password_clear']) && $user['password_clear'])
			{
				$now = JFactory::getDate();
				$data_passwordpolicy['pwdLastSet'] = $now->toSql();

				if ($enforcePasswordHistory = $this->params->get('enforcePasswordHistory', 0))
				{
					if (!isset($data_passwordpolicy['passwordHistory']))
					{
						$data_passwordpolicy['passwordHistory'] = array($user['password']);
					}
					else
					{
						if (count($data_passwordpolicy['passwordHistory']) >= $enforcePasswordHistory)
						{
							array_pop($data_passwordpolicy['passwordHistory']);
						}
						array_unshift($data_passwordpolicy['passwordHistory'], $user['password']);
					}
				}
			}
			JLog::add(new JLogEntry('data_passwordpolicy: '.print_r($data_passwordpolicy, true), JLog::DEBUG, 'plg_user_passwordpolicy'));

			try
			{
				$db = JFactory::getDbo();
				$query = $db->getQuery(true)
					->delete($db->qn('#__user_profiles'))
					->where($db->qn('user_id') . ' = ' . $userId)
					->where($db->qn('profile_key') . ' LIKE ' . $db->q('passwordpolicy.%'));
				JLog::add(new JLogEntry($query, JLog::DEBUG, 'plg_user_passwordpolicy'));
				if (!$db->setQuery($query)->query()) {
					throw new Exception($db->getErrorMsg());
				}

				$query = $db->getQuery(true)
				   ->insert($db->qn('#__user_profiles'));

				$tuples = array();
				$order	= 1;
				foreach ($data_passwordpolicy as $k => $v) {
					$query->values($userId.', '.$db->quote('passwordpolicy.'.$k).', '.$db->quote(json_encode($v)).', '.$order++);
				}

				JLog::add(new JLogEntry($query, JLog::DEBUG, 'plg_user_passwordpolicy'));
				if (!$db->setQuery($query)->query()) {
					throw new Exception($db->getErrorMsg());
				}
			}
			catch (JException $e) {
				$this->_subject->setError($e->getMessage());
				return false;
			}
		}

		return true;
	}

	/**
	 * Remove all user profile information for the given user ID
	 *
	 * Method is called after user data is deleted from the database
	 *
	 * @param	array		$user		Holds the user data
	 * @param	boolean		$success	True if user was succesfully stored in the database
	 * @param	string		$msg		Message
	 *
	 * @return  boolean
	 */
	function onUserAfterDelete($user, $success, $msg)
	{
		JLog::add(new JLogEntry(__METHOD__, JLog::DEBUG, 'plg_user_passwordpolicy'));
		if (!$success) {
			return false;
		}

		$userId	= JArrayHelper::getValue($user, 'id', 0, 'int');

		if ($userId)
		{
			try
			{
				$db = JFactory::getDbo();
				$query = $db->getQuery(true)
					->delete($db->qn('#__user_profiles'))
					->where($db->qn('user_id') . ' = ' . $userId)
					->where($db->qn('profile_key') . ' LIKE ' . $db->q('passwordpolicy.%'));
				JLog::add(new JLogEntry($query, JLog::DEBUG, 'plg_user_passwordpolicy'));
				if (!$db->setQuery($query)->query()) {
					throw new Exception($db->getErrorMsg());
				}
			}
			catch (JException $e)
			{
				JLog::add(new JLogEntry($e->getMessage(), JLog::ERROR, 'plg_user_passwordpolicy'));
				$this->_subject->setError($e->getMessage());
				return false;
			}
		}

		return true;
	}

	/**
	 * Runs on content preparation
	 *
	 * @param   string  $context  The context for the data
	 * @param   object  $data	 An object containing the data for the form.
	 *
	 * @return  boolean
	 */
	public function onContentPrepareData($context, $data)
	{
		JLog::add(new JLogEntry(__METHOD__, JLog::DEBUG, 'plg_user_passwordpolicy'));
		JLog::add(new JLogEntry($context, JLog::DEBUG, 'plg_user_passwordpolicy'));
		// Check we are manipulating a valid form.
		//if (!in_array($context, array('com_users.profile','com_users.registration','com_users.user','com_admin.profile'))){
		if (!in_array($context, array('com_users.profile', 'com_users.user'))){
			return true;
		}

		if (is_object($data))
		{
			$userId = isset($data->id) ? $data->id : 0;

			// Load the profile data from the database.
			$db = JFactory::getDbo();
			$db->setQuery($query = $db->getQuery(true)
				->select(array('profile_key','profile_value'))
				->from($db->qn('#__user_profiles'))
				->where($db->qn('user_id') . ' = ' . $userId)
				->where($db->qn('profile_key') . ' LIKE ' . $db->q('passwordpolicy.%'))
				->order($db->qn('ordering'))
				);
			JLog::add(new JLogEntry($query, JLog::DEBUG, 'plg_user_passwordpolicy'));
			$results = $db->loadRowList();
			JLog::add(new JLogEntry(print_r($results, true), JLog::DEBUG, 'plg_user_passwordpolicy'));

			// Check for a database error.
			if ($db->getErrorNum()) {
				$this->_subject->setError($db->getErrorMsg());
				return false;
			}

			// Merge the profile data.
			$data->passwordpolicy = array();
			foreach ($results as $v) {
				$k = str_replace('passwordpolicy.', '', $v[0]);
				$data->passwordpolicy[$k] = json_decode($v[1], true);
			}
		}

		return true;
	}

	/**
	 * Adds additional fields to the user editing form
	 *
	 * @param   JForm  $form  The form to be altered.
	 * @param   mixed  $data  The associated data for the form.
	 *
	 * @return  boolean
	 */
	public function onContentPrepareForm($form, $data)
	{
		JLog::add(new JLogEntry(__METHOD__, JLog::DEBUG, 'plg_user_passwordpolicy'));
		JLog::add(new JLogEntry(print_r($data, true), JLog::DEBUG, 'plg_user_passwordpolicy'));

		if (!($form instanceof JForm))
		{
			$this->_subject->setError('JERROR_NOT_A_FORM');

			return false;
		}

		// Check we are manipulating a valid form.
		$name = $form->getName();
		JLog::add(new JLogEntry($name, JLog::DEBUG, 'plg_user_passwordpolicy'));

		//if (!in_array($name, array('com_admin.profile', 'com_users.user', 'com_users.profile', 'com_users.registration')))
		if (!in_array($name, array('com_users.user')))
		{
			return true;
		}

		// Add the registration fields to the form.
		JForm::addFormPath(__DIR__ . '/profiles');
		$form->loadFile('profile', false);
	}

	/**
	 * Method is called before user data is stored in the database
	 *
	 * @param   array	$user   Holds the old user data.
	 * @param   boolean  $isnew  True if a new user is stored.
	 * @param   array	$data   Holds the new user data.
	 *
	 * @return	boolean
	 *
	 * @since   3.8.2
	 * @throws	InvalidArgumentException on invalid date.
	 */
	public function onUserBeforeSave($user, $isnew, $data)
	{
		JLog::add(new JLogEntry(__METHOD__, JLog::DEBUG, 'plg_user_passwordpolicy'));

		if (JFactory::getApplication()->isAdmin())
		{
			if ($user['block'] && !$data['block'])
			{
				$query = $db->getQuery(true)
					->delete($db->qn('#__user_profiles'))
					->where($db->qn('user_id') . ' = ' . $user['id'])
					->where($db->qn('profile_key') . ' LIKE ' . $db->q('passwordpolicy.expiryDate'));
				JLog::add(new JLogEntry($query, JLog::DEBUG, 'plg_user_passwordpolicy'));
				if (!$db->setQuery($query)->query()) {
					throw new Exception($db->getErrorMsg());
				}
			}

			return true;
		}

		// Load the profile data from the database.
		$db = JFactory::getDbo();
		$db->setQuery($query = $db->getQuery(true)
				->select(array('profile_key','profile_value'))
				->from($db->qn('#__user_profiles'))
				->where($db->qn('user_id') . ' = ' . $user['id'])
				->where($db->qn('profile_key') . ' LIKE ' . $db->q('passwordpolicy.%'))
				->order($db->qn('ordering'))
				);
		JLog::add(new JLogEntry($query, JLog::DEBUG, 'plg_user_passwordpolicy'));
		$results = $db->loadRowList();
		JLog::add(new JLogEntry(print_r($results, true), JLog::DEBUG, 'plg_user_passwordpolicy'));
		
		// Check for a database error.
		if ($db->getErrorNum()) {
			$this->_subject->setError($db->getErrorMsg());
			return false;
		}
		
		$passwordpolicy = array();
		foreach ($results as $v)
		{
			$k = str_replace('passwordpolicy.', '', $v[0]);
			$passwordpolicy[$k] = json_decode($v[1], true);
		}
		
		if (!$isnew && $data['password_clear'])
		{
			if (($user['requireReset'] == 0) && ($minimumPasswordAge = $this->params->get('minimumPasswordAge', 0)))
			{
				$today = JFactory::getDate();

				if (isset($passwordpolicy['maximumPasswordAge']) && $passwordpolicy['maximumPasswordAge'] && ((int)$passwordpolicy['maximumPasswordAge'] <= $minimumPasswordAge))
				{
					$minimumPasswordAge = $passwordpolicy['maximumPasswordAge'] - 1;
				}

				$date = new JDate((isset($passwordpolicy['pwdLastSet']) ? $passwordpolicy['pwdLastSet'] : $user->registerDate) . ' + ' . $minimumPasswordAge . ' days');

				JLog::add(new JLogEntry('date: ' . $date, JLog::DEBUG, 'plg_user_passwordpolicy'));
				if ($date > $today)
				{
					$this->_subject->setError(JText::_('PLG_USER_PASSWORDPOLICY_UNABLETOUPDATEPASSWORD'));
					// $this->_subject->setError() doesn't work
					JLog::add(new JLogEntry(JText::_('PLG_USER_PASSWORDPOLICY_UNABLETOUPDATEPASSWORD'), JLog::WARNING, 'plg_user_passwordpolicy'));
					return false;
				}
			}

			if ($enforcePasswordHistory = $this->params->get('enforcePasswordHistory', 0))
			{
				if (isset($passwordpolicy['passwordHistory']))
				{
					foreach ($passwordpolicy['passwordHistory'] as $password)
					{
						if (JUserHelper::verifyPassword($data['password_clear'], $password, 0))
						{
							$this->_subject->setError(JText::_('PLG_USER_PASSWORDPOLICY_UNABLETOUPDATEPASSWORD'));
							// $this->_subject->setError() doesn't work
							JLog::add(new JLogEntry(JText::_('PLG_USER_PASSWORDPOLICY_UNABLETOUPDATEPASSWORD'), JLog::WARNING, 'plg_user_passwordpolicy'));
							return false;
						}
					}
				}
			}
		}

		return true;
	}

	/**
	 * This method should handle whenever you would like to authorize a user by additional criteria.
	 *
	 * @param   JAuthenticationResponse $user
	 * @param   array	$options Array of extra options
	 *
	 * @return  null|JAuthenticationResponse
	 */
	public function onUserAuthorisation($user, $options)
	{
		JLog::add(new JLogEntry(__METHOD__, JLog::DEBUG, 'plg_user_passwordpolicy'));
		JLog::add(new JLogEntry(print_r($user, true), JLog::DEBUG, 'plg_user_passwordpolicy'));

		$userId   = JUserHelper::getUserId($user->username);
		$db		  = JFactory::getDbo();
		$nullDate = $db->getNullDate();
		$today	= JFactory::getDate();

		$query	= $db->getQuery(true)
			->select(array('profile_key', 'profile_value'))
			->from($db->qn('#__user_profiles'))
			->where($db->qn('user_id') . ' = ' . $userId)
			->where($db->qn('profile_key') . ' LIKE ' . $db->q('passwordpolicy.%'))
			->order('ordering');
		$db->setQuery($query);

		try
		{
			$results = $db->loadRowList();
		}
		catch (RuntimeException $e)
		{
			$this->_subject->setError($e->getMessage());

			return null;
		}

		// Get the password policy data.
		$passwordpolicy = array();
		foreach ($results as $v)
		{
			$k = str_replace('passwordpolicy.', '', $v[0]);
			$passwordpolicy[$k] = json_decode($v[1], true);

			if ($passwordpolicy[$k] === null)
			{
				$passwordpolicy[$k] = $v[1];
			}
		}

		if (isset($passwordpolicy['expiryDate']) &&  $passwordpolicy['expiryDate'])
		{
			JLog::add(new JLogEntry('expiryDate: ' . $passwordpolicy['expiryDate'], JLog::DEBUG, 'plg_user_passwordpolicy'));

			$date = new JDate($passwordpolicy['expiryDate']);

			JLog::add(new JLogEntry('today: ' . $today->toSql(), JLog::DEBUG, 'plg_user_passwordpolicy'));
			JLog::add(new JLogEntry('expitation date: ' . $date->toSql(), JLog::DEBUG, 'plg_user_passwordpolicy'));

			if ($date < $today)
			{
				// Update the block flag
				try
				{
					JLog::add(new JLogEntry('Your user account has expired', JLog::DEBUG, 'plg_user_passwordpolicy'));
					$db->setQuery($db->getQuery(true)
						->update($db->qn('#__users'))
						->set($db->qn('block') . ' = 1')
						->where($db->qn('id') . ' = ' . $userId)
						)->execute();
				}
				catch (RuntimeException $e)
				{
				}
			}
		}
		else
		{
			JLog::add(new JLogEntry('Account never expires', JLog::DEBUG, 'plg_user_passwordpolicy'));
		}
	}
}