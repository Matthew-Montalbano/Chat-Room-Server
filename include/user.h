/**
 * === DO NOT MODIFY THIS FILE ===
 * If you need some other prototypes or constants in a header, please put them
 * in another header file.
 *
 * When we grade, we will be replacing this file with our own copy.
 * You have been warned.
 * === DO NOT MODIFY THIS FILE ===
 */
#ifndef USER_H
#define USER_H

/*
 * A USER represents a user of the system.
 * A user has a handle, which does not change, and possibly other information.
 * USER objects are managed by the user registry, where they persist across
 * login sessions.  So that a USER object can be passed around externally
 * to the user registry without fear of dangling references, it has a
 * reference count that corresponds to the number of references that exist
 * to the object.  A USER object will not be freed until its reference
 * count reaches zero.
 */

/*
 * The USER type is a structure type that defines the state of a user.
 * You will have to give a complete structure definition in user.c.
 * The precise contents are up to you.  Be sure that all the operations
 * that might be called concurrently are thread-safe.
 */
typedef struct user USER;

/*
 * Create a new USER with a specified handle.  A private copy is
 * made of the handle that is passed.  The newly created USER has
 * a reference count of one, corresponding to the reference that is
 * returned from this function.
 *
 * @param handle  The handle of the USER.
 * @return  A reference to the newly created USER, if initialization
 * was successful, otherwise NULL.
 */
USER *user_create(char *handle);

/*
 * Increase the reference count on a user by one.
 *
 * @param user  The USER whose reference count is to be increased.
 * @param why  A string describing the reason why the reference count is
 * being increased.  This is used for debugging printout, to help trace
 * the reference counting.
 * @return  The same USER object that was passed as a parameter.
 */
USER *user_ref(USER *user, char *why);

/*
 * Decrease the reference count on a USER by one.
 * If after decrementing, the reference count has reached zero, then the
 * USER and its contents are freed.
 *
 * @param user  The USER whose reference count is to be decreased.
 * @param why  A string describing the reason why the reference count is
 * being decreased.  This is used for debugging printout, to help trace
 * the reference counting.
 *
 */
void user_unref(USER *user, char *why);

/*
 * Get the handle of a user.
 *
 * @param user  The USER that is to be queried.
 * @return the handle of the user.
 */
char *user_get_handle(USER *user);

#endif
