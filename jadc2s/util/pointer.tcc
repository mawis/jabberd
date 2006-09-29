/*
 * Licence
 *
 * You can use the content of this file using one of the following licences:
 *
 * - Version 1.0 of the Jabber Open Source Licence ("JOSL")
 * - GNU GENERAL PUBLIC LICENSE, Version 2 or any newer version of this licence at your choice
 * - Apache Licence, Version 2.0
 * - GNU Lesser General Public License, Version 2.1 or any newer version of this licence at your choice
 * - Mozilla Public License 1.1
 */

/**
 * @file pointer.tcc
 * @brief managed pointer
 *
 * This file implements the pointer<pointed_type> template class.
 */

#include <cassert>
#include <cstdlib>

namespace xmppd {

    template<class pointed_type> pointer<pointed_type>::pointer(pointed_type* pointed_object, bool malloc_allocated) : pointed_object(pointed_object), all_pointers_to_this_object(NULL), malloc_allocated(malloc_allocated) {
	if (pointed_object != NULL) {
	    all_pointers_to_this_object = new std::set<pointer<pointed_type>*>;
	    all_pointers_to_this_object->insert(this);
	}
    }

    template<class pointed_type> pointer<pointed_type>::pointer(const pointer<pointed_type>& src) : pointed_object(src.pointed_object), all_pointers_to_this_object(src.all_pointers_to_this_object), malloc_allocated(malloc_allocated) {
	if (pointed_object != NULL && all_pointers_to_this_object != NULL) {
	    all_pointers_to_this_object->insert(this);
	}
    }

    template<class pointed_type> pointer<pointed_type>::~pointer() {
	// the following will update the set of pointers pointing to the object, and if needed delete the object
	point_nothing();

	// that's all we have to do
    }

    template<class pointed_type> void pointer<pointed_type>::delete_object() {
	// we have to make a copy, as we delete this in the iteration
	std::set< pointer<pointed_type>* > set_copy = *all_pointers_to_this_object;

	// let all pointers pointing to this object point to nothing, the object will then get deleted by the last call to point_nothing()
	typename std::set< pointer<pointed_type>* >::iterator p;
	for (p=set_copy.begin(); p!=set_copy.end(); ++p) {
	    (*p)->point_nothing();
	}
    }

    template<class pointed_type> pointer<pointed_type>& pointer<pointed_type>::operator=(const pointer<pointed_type>& src) {
	// remove link to the object we pointed to until now
	point_nothing();

	// copy the data
	pointed_object = src.pointed_object;
	all_pointers_to_this_object = src.all_pointers_to_this_object;
	malloc_allocated = src.malloc_allocated;

	// add us to the set of pointers to this object
	if (pointed_object != NULL && all_pointers_to_this_object != NULL) {
	    all_pointers_to_this_object->insert(this);
	}
    }

    template<class pointed_type> pointed_type& pointer<pointed_type>::operator*() {
	return *operator->();
    }

    template<class pointed_type> pointed_type* pointer<pointed_type>::operator->() {
	// are we currently pointing to anything?
	if (pointed_object == NULL) {
	    assert(all_pointers_to_this_object == NULL);

	    // we are pointing to nothing, throw an exception
	    throw std::string("Access to a managed pointer, pointing to nothing");
	}

	// debugging check
	assert(all_pointers_to_this_object != NULL);

	return pointed_object;
    }

    template<class pointed_type> void pointer<pointed_type>::point_nothing() {
	// if we are pointing to thing, we do not have to do anything
	if (all_pointers_to_this_object == NULL) {
	    assert(pointed_object == NULL);
	    return;
	}

	// we are pointing to something
	
	// remove us from the list of managed pointers to the object
	all_pointers_to_this_object->erase(all_pointers_to_this_object->find(this));

	// are we the last pointer pointing to this object? then we have to delete (free) the object
	if (all_pointers_to_this_object->empty()) {
	    if (malloc_allocated) {
		std::free(pointed_object);
	    } else {
		delete pointed_object;
	    }

	    delete all_pointers_to_this_object;
	}

	// we are now pointing to nothing
	all_pointers_to_this_object = NULL;
	pointed_object = NULL;
    }
}
