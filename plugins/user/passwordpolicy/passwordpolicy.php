<?php
/**
 * @package		Password policy
 * @subpackage	plg_user_passwordpolicy
 *
 * @author		Helios Ciancio <info@eshiol.it>
 * @link		http://www.eshiol.it
 * @copyright	Copyright (C) 2018, 2019 Helios Ciancio. All Rights Reserved
 * @license		http://www.gnu.org/licenses/gpl-3.0.html GNU/GPL v3
 * Password Policy for Joomla! is free software. This version may have been
 * modified pursuant to the GNU General Public License, and as distributed
 * it includes or is derivative of works licensed under the GNU General Public
 * License or other free or open source software licenses.
 */

// no direct access
defined('_JEXEC') or die('Restricted access.');

jimport('joomla.plugin.plugin');

if ((new JVersion())->isCompatible ('3.9'))
{
	JModelLegacy::addIncludePath(JPATH_ADMINISTRATOR . '/components/com_actionlogs/models', 'ActionlogsModel');
}

class plgUserPasswordpolicy extends JPlugin
{
	/**
	 * Application object
	 *
	 * @var JApplicationCms
	 * @since 3.8.4
	 */
	protected $app;

	/**
	 * Load the language file on instantiation.
	 *
	 * @var boolean
	 */
	protected $autoloadLanguage = true;

	/**
	 * Database object
	 *
	 * @var JDatabaseDriver
	 * @since 3.8.4.1
	 */
	protected $db;

	/**
	 * This method should handle whenever you would like to authorize a user by additional criteria.
	 *
	 * @param JAuthenticationResponse $user
	 * @param array $options
	 *        	Array of extra options
	 *        
	 * @return null|JAuthenticationResponse
	 */
	public function onUserAuthorisation($user, $options)
	{
		$userId = JUserHelper::getUserId($user->username);
		$now = new JDate();
		$nullDate = $this->db->getNullDate();

		$query = $this->db->getQuery(true)
			->select(array(
			'profile_key',
			'profile_value'
		))
			->from($this->db->quoteName('#__user_profiles'))
			->where($this->db->quoteName('user_id') . ' = ' . $userId)
			->where($this->db->quoteName('profile_key') . ' LIKE ' . $this->db->quote('passwordpolicy.%'))
			->order('ordering');
		$this->db->setQuery($query);

		try {
			$results = $this->db->loadRowList();
		} catch (RuntimeException $e) {
			$this->_subject->setError($e->getMessage());

			return null;
		}

		// Get the password policy data.
		$passwordpolicy = array();
		foreach ($results as $v) {
			$k = str_replace('passwordpolicy.', '', $v[0]);
			$passwordpolicy[$k] = json_decode($v[1], true);

			if ($passwordpolicy[$k] === null) {
				$passwordpolicy[$k] = $v[1];
			}
		}

		if (isset($passwordpolicy['expiryDate']) && $passwordpolicy['expiryDate']) {
			$date = new JDate($passwordpolicy['expiryDate']);

			if ($date < $now) {
				// Update the block flag
				try {
					$query = $this->db->getQuery(true)
						->update($this->db->quoteName('#__users'))
						->set($this->db->quoteName('block') . ' = 1')
						->where($this->db->quoteName('id') . ' = ' . $userId);
					$this->db->setQuery($query)->execute();

					if ((new JVersion())->isCompatible ('3.9'))
					{
						/** @var ActionlogsModelActionlog $model **/
						$model = JModelLegacy::getInstance('Actionlog', 'ActionlogsModel');
						$message = array(
							'action' => 'update',
							'type' => 'PLG_ACTIONLOG_JOOMLA_TYPE_USER',
							'id' => $userId,
							'title' => $user->fullname,
							'itemlink' => 'index.php?option=com_users&task=user.edit&id=' . $userId,
							'userid' => $userId,
							'username' => $user->username,
							'accountlink' => 'index.php?option=com_users&task=user.edit&id=' . $userId
						);
						$model->addLog(array(
							$message
						), 'PLG_SYSTEM_ACTIONLOGS_CONTENT_UPDATED', 'plg_user_passwordpolicy', $userId);
					}
				} catch (RuntimeException $e) {}
			}
		}
	}

	/**
	 * This event is triggered whenever a user is successfully logged in.
	 *
	 * @param array $options
	 *        	Array holding options (remember, return, entry_url, action, user - JUser Object, responseType)
	 *        
	 * @return boolean True on success
	 */
	public function onUserAfterLogin($options)
	{
		$user = $options['user'];
		$userId = $user->id;
		$now = new JDate();
		$nullDate = $this->db->getNullDate();

		$query = $this->db->getQuery(true)
			->select(array(
			'profile_key',
			'profile_value'
		))
			->from($this->db->quoteName('#__user_profiles'))
			->where($this->db->quoteName('user_id') . ' = ' . $userId)
			->where($this->db->quoteName('profile_key') . ' LIKE ' . $this->db->quote('passwordpolicy.%'))
			->order('ordering');
		$this->db->setQuery($query);

		try {
			$results = $this->db->loadRowList();
		} catch (RuntimeException $e) {
			$this->_subject->setError($e->getMessage());

			return false;
		}

		// Get the password policy data.
		$passwordpolicy = array();
		foreach ($results as $v) {
			$k = str_replace('passwordpolicy.', '', $v[0]);
			$passwordpolicy[$k] = json_decode($v[1], true);

			if ($passwordpolicy[$k] === null) {
				$passwordpolicy[$k] = $v[1];
			}
		}

		if (isset($passwordpolicy['maximumPasswordAge']) && $passwordpolicy['maximumPasswordAge']) {
			$passwordpolicy['maximumPasswordAge'] = min($passwordpolicy['maximumPasswordAge'], (int) $this->params->get('maximumPasswordAge'), $passwordpolicy['maximumPasswordAge']);
		} else {
			$passwordpolicy['maximumPasswordAge'] = (int) $this->params->get('maximumPasswordAge');
		}

		if ($passwordpolicy['maximumPasswordAge']) {
			$date = new JDate((isset($passwordpolicy['pwdLastSet']) ? $passwordpolicy['pwdLastSet'] : $user->registerDate) . ' + ' . $passwordpolicy['maximumPasswordAge'] . ' days');

			if ($date < $now) {
				// Update the reset flag
				try {
					$this->db->setQuery($this->db->getQuery(true)
						->update($this->db->quoteName('#__users'))
						->set($this->db->quoteName('requireReset') . ' = 1')
						->where($this->db->quoteName('id') . ' = ' . $user->id))
						->execute();
				} catch (RuntimeException $e) {}
			} elseif ($this->params->get('passwordExpirationReminder', 1)) {
				if (($days = $now->diff($date)->format('%a') + 1) == 1) {
					JLog::add(new JLogEntry(JText::sprintf('PLG_USER_PASSWORDPOLICY_PASSWORDLLEXPIREIN_1', $days), JLog::WARNING, 'plg_user_passwordpolicy'));
				} elseif (in_array($days, array(
					2,
					3,
					7,
					15,
					30
				))) {
					JLog::add(new JLogEntry(JText::sprintf('PLG_USER_PASSWORDPOLICY_PASSWORDLLEXPIREIN', $days), JLog::WARNING, 'plg_user_passwordpolicy'));
				}
			}
		}

		if ($this->app->isAdmin()) {
			$query = $this->db->getQuery(true);
			$query->select($this->db->quoteName('id'))
				->from($this->db->quoteName('#__users', 'u'))
				->from($this->db->quoteName('#__user_profiles', 'p'))
				->where($this->db->quoteName('u.id') . ' = ' . $this->db->quoteName('p.user_id'))
				->where($this->db->quoteName('p.profile_key') . ' = ' . $this->db->quote('passwordpolicy.expiryDate'))
				->where($this->db->quoteName('p.profile_value') . ' < ' . $this->db->quote('"' . $now->toSql() . '"'))
				->where($this->db->quoteName('p.profile_value') . ' <> ' . $this->db->quote('""'))
				->where($this->db->quoteName('u.block') . ' = 0');

			$pks = $this->db->setQuery($query)->loadColumn();

			// Prepare the logout options.
			$options = array(
				'clientid' => $this->app->get('shared_session', '0') ? null : 0,
				'context' => 'plg_user_passwordpolicy'
			);

			if ((new JVersion())->isCompatible ('3.9'))
			{
				/** @var ActionlogsModelActionlog $model **/
				$model = JModelLegacy::getInstance('Actionlog', 'ActionlogsModel');
			}

			foreach ($pks as $id) {
				// Update the block flag
				try {
					$query = $this->db->getQuery(true)
						->update($this->db->quoteName('#__users'))
						->set($this->db->quoteName('block') . ' = 1')
						->where($this->db->quoteName('id') . ' = ' . $id);
					$this->db->setQuery($query)->execute();

					$tmp_user = JFactory::getUser($id);

					if ((new JVersion())->isCompatible ('3.9'))
					{
						$message = array(
							'action' => 'update',
							'type' => 'PLG_ACTIONLOG_JOOMLA_TYPE_USER',
							'id' => $id,
							'title' => $tmp_user->name,
							'itemlink' => 'index.php?option=com_users&task=user.edit&id=' . $id,
							'userid' => $userId,
							'username' => $user->username,
							'accountlink' => 'index.php?option=com_users&task=user.edit&id=' . $userId
						);
						$model->addLog(array(
							$message
						), 'PLG_SYSTEM_ACTIONLOGS_CONTENT_UPDATED', 'plg_user_passwordpolicy', $userId);
					}
					$this->app->logout($id, $options);
				} catch (RuntimeException $e) {}
			}
		}

		return true;
	}

	/**
	 * Runs on content preparation
	 *
	 * @param string $context
	 *        	The context for the data
	 * @param object $data
	 *        	An object containing the data for the form.
	 *        
	 * @return boolean
	 */
	public function onContentPrepareData($context, $data)
	{
		// Check we are manipulating a valid form.
		// if (!in_array($context, array('com_users.profile','com_users.registration','com_users.user','com_admin.profile'))){
		if (! in_array($context, array(
			'com_users.profile',
			'com_users.user'
		))) {
			return true;
		}

		if (is_object($data)) {
			$userId = isset($data->id) ? $data->id : 0;

			// Load the profile data from the database.
			$this->db->setQuery($query = $this->db->getQuery(true)
				->select(array(
				'profile_key',
				'profile_value'
			))
				->from($this->db->quoteName('#__user_profiles'))
				->where($this->db->quoteName('user_id') . ' = ' . $userId)
				->where($this->db->quoteName('profile_key') . ' LIKE ' . $this->db->quote('passwordpolicy.%'))
				->order($this->db->quoteName('ordering')));
			$results = $this->db->loadRowList();

			// Check for a database error.
			if ($this->db->getErrorNum()) {
				$this->_subject->setError($this->db->getErrorMsg());
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
	 * @param JForm $form
	 *        	The form to be altered.
	 * @param mixed $data
	 *        	The associated data for the form.
	 *        
	 * @return boolean
	 */
	public function onContentPrepareForm($form, $data)
	{
		if (! ($form instanceof JForm)) {
			$this->_subject->setError('JERROR_NOT_A_FORM');

			return false;
		}

		// Check we are manipulating a valid form.
		$name = $form->getName();

		// if (!in_array($name, array('com_admin.profile', 'com_users.user', 'com_users.profile', 'com_users.registration')))
		if (! in_array($name, array(
			'com_users.user'
		))) {
			return true;
		}

		// Add the registration fields to the form.
		JForm::addFormPath(__DIR__ . '/profiles');
		$form->loadFile('profile', false);
	}

	/**
	 * Method is called before user data is stored in the database
	 *
	 * @param array $user
	 *        	Holds the old user data.
	 * @param boolean $isnew
	 *        	True if a new user is stored.
	 * @param array $data
	 *        	Holds the new user data.
	 *        
	 * @return boolean
	 *
	 * @since 3.8.2
	 * @throws InvalidArgumentException on invalid date.
	 */
	public function onUserBeforeSave($user, $isnew, $data)
	{
		$now = new JDate();

		// Load the profile data from the database.
		$this->db->setQuery($query = $this->db->getQuery(true)
			->select(array(
			'profile_key',
			'profile_value'
		))
			->from($this->db->quoteName('#__user_profiles'))
			->where($this->db->quoteName('user_id') . ' = ' . $user['id'])
			->where($this->db->quoteName('profile_key') . ' LIKE ' . $this->db->quote('passwordpolicy.%'))
			->order($this->db->quoteName('ordering')));
		$results = $this->db->loadRowList();

		// Check for a database error.
		if ($this->db->getErrorNum()) {
			$this->_subject->setError($this->db->getErrorMsg());
			return false;
		}

		$passwordpolicy = array();
		foreach ($results as $v) {
			$k = str_replace('passwordpolicy.', '', $v[0]);
			$passwordpolicy[$k] = json_decode($v[1], true);
		}

		if (! $isnew && $data['password_clear']) {
			if (($user['requireReset'] == 0) && ($minimumPasswordAge = $this->params->get('minimumPasswordAge', 0))) {
				if (isset($passwordpolicy['maximumPasswordAge']) && $passwordpolicy['maximumPasswordAge'] && ((int) $passwordpolicy['maximumPasswordAge'] <= $minimumPasswordAge)) {
					$minimumPasswordAge = $passwordpolicy['maximumPasswordAge'] - 1;
				}

				$date = new JDate((isset($passwordpolicy['pwdLastSet']) ? $passwordpolicy['pwdLastSet'] : $user->registerDate) . ' + ' . $minimumPasswordAge . ' days');

				if ($date > $now) {
					$this->_subject->setError(JText::_('PLG_USER_PASSWORDPOLICY_UNABLETOUPDATEPASSWORD'));
					// $this->_subject->setError() doesn't work
					JLog::add(new JLogEntry(JText::_('PLG_USER_PASSWORDPOLICY_UNABLETOUPDATEPASSWORD'), JLog::WARNING, 'plg_user_passwordpolicy'));
					return false;
				}
			}

			if ($enforcePasswordHistory = $this->params->get('enforcePasswordHistory', 0)) {
				if (isset($passwordpolicy['passwordHistory'])) {
					foreach ($passwordpolicy['passwordHistory'] as $password) {
						if (JUserHelper::verifyPassword($data['password_clear'], $password, 0)) {
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
	 * Utility method to act on a user after it has been saved.
	 *
	 * This method sends a registration email to new users created in the backend.
	 *
	 * @param array $user
	 *        	Holds the new user data.
	 * @param boolean $isnew
	 *        	True if a new user is stored.
	 * @param boolean $success
	 *        	True if user was successfully stored in the database.
	 * @param string $msg
	 *        	Message.
	 *        
	 * @return void
	 */
	
	public function onUserAfterSave($user, $isnew, $success, $msg)
	{
		$userId = JArrayHelper::getValue($user, 'id', 0, 'int');
		$now = new JDate();

		if ($userId && $success) {
			// Load the profile data from the database.
			$this->db->setQuery($query = $this->db->getQuery(true)
				->select(array(
				'profile_key',
				'profile_value'
			))
				->from($this->db->quoteName('#__user_profiles'))
				->where($this->db->quoteName('user_id') . ' = ' . $userId)
				->where($this->db->quoteName('profile_key') . ' LIKE ' . $this->db->quote('passwordpolicy.%'))
				->order($this->db->quoteName('ordering')));
			$results = $this->db->loadRowList();

			// Merge the profile data.
			$passwordpolicy = array();
			foreach ($results as $v) {
				$k = str_replace('passwordpolicy.', '', $v[0]);
				$passwordpolicy[$k] = json_decode($v[1], true);
			}

			if (isset($user['passwordpolicy']) && (count($user['passwordpolicy']))) {
				unset($user['passwordpolicy']['pwdLastSet']);
				foreach ($user['passwordpolicy'] as $k => $v) {
					$passwordpolicy[$k] = $v;
				}
			}

			if (isset($user['password_clear']) && $user['password_clear']) {
				$passwordpolicy['pwdLastSet'] = $now->toSql();

				if ($enforcePasswordHistory = $this->params->get('enforcePasswordHistory', 0)) {
					if (! isset($passwordpolicy['passwordHistory'])) {
						$passwordpolicy['passwordHistory'] = array(
							$user['password']
						);
					} else {
						if (count($passwordpolicy['passwordHistory']) >= $enforcePasswordHistory) {
							array_pop($passwordpolicy['passwordHistory']);
						}
						array_unshift($passwordpolicy['passwordHistory'], $user['password']);
					}
				}
			}

			if (! $user['block'] && isset($passwordpolicy['expiryDate'])) {
				$expiryDate = new JDate($passwordpolicy['expiryDate']);
				if ($expiryDate < $now) {
					unset($passwordpolicy['expiryDate']);
				}
			}

			try {
				$query = $this->db->getQuery(true)
					->delete($this->db->quoteName('#__user_profiles'))
					->where($this->db->quoteName('user_id') . ' = ' . $userId)
					->where($this->db->quoteName('profile_key') . ' LIKE ' . $this->db->quote('passwordpolicy.%'));
				if (! $this->db->setQuery($query)->query()) {
					throw new Exception($this->db->getErrorMsg());
				}

				$query = $this->db->getQuery(true)->insert($this->db->quoteName('#__user_profiles'));

				$tuples = array();
				$order = 1;
				foreach ($passwordpolicy as $k => $v) {
					$query->values($userId . ', ' . $this->db->quote('passwordpolicy.' . $k) . ', ' . $this->db->quote(json_encode($v)) . ', ' . $order ++);
				}

				if (! $this->db->setQuery($query)->query()) {
					throw new Exception($this->db->getErrorMsg());
				}
			} catch (JException $e) {
				$this->_subject->setError($e->getMessage());
				$success = false;
			}
		}
	}

	/**
	 * Remove all user profile information for the given user ID
	 *
	 * Method is called after user data is deleted from the database
	 *
	 * @param array $user
	 *        	Holds the user data
	 * @param boolean $success
	 *        	True if user was succesfully stored in the database
	 * @param string $msg
	 *        	Message
	 *        
	 * @return boolean
	 */
	function onUserAfterDelete($user, $success, $msg)
	{
		if (! $success) {
			return false;
		}

		$userId = JArrayHelper::getValue($user, 'id', 0, 'int');

		if ($userId) {
			try {
				$query = $this->db->getQuery(true)
					->delete($this->db->quoteName('#__user_profiles'))
					->where($this->db->quoteName('user_id') . ' = ' . $userId)
					->where($this->db->quoteName('profile_key') . ' LIKE ' . $this->db->quote('passwordpolicy.%'));
				if (! $this->db->setQuery($query)->query()) {
					throw new Exception($this->db->getErrorMsg());
				}
			} catch (JException $e) {
				JLog::add(new JLogEntry($e->getMessage(), JLog::ERROR, 'plg_user_passwordpolicy'));
				$this->_subject->setError($e->getMessage());
				return false;
			}
		}

		return true;
	}
}