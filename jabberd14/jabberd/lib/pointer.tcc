/*
 * Copyrights
 * 
 * Copyright (c) 2006-2007 Matthias Wimmer
 *
 * This file is part of jabberd14.
 *
 * This software is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this software; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 */

/**
 * @file pointer.tcc
 * @brief managed pointer
 *
 * This file implements the pointer<pointed_type> template class.
 *
 * The functionality is similar to std::tr1::shared_ptr<>
 */

#include <cassert>
#include <cstdlib>

namespace xmppd {
    template<class pointed_type> pointer<pointed_type>::pointer() : pointed_object(NULL), all_pointers_to_this_object(NULL) {
    }

    template<class pointed_type> pointer<pointed_type>::pointer(pointed_type* pointed_object, bool malloc_allocated) : pointed_object(pointed_object), all_pointers_to_this_object(NULL), malloc_allocated(malloc_allocated) {
	if (pointed_object != NULL) {
	    all_pointers_to_this_object = new std::set<pointer<pointed_type>*>;
	    assert(this->pointed_object != NULL);
	    all_pointers_to_this_object->insert(this);
	}

	assert((all_pointers_to_this_object == NULL) == (pointed_object == NULL));
    }

    template<class pointed_type> pointer<pointed_type>::pointer(const pointer<pointed_type>& src) : pointed_object(src.pointed_object), all_pointers_to_this_object(src.all_pointers_to_this_object), malloc_allocated(malloc_allocated) {
	if (pointed_object != NULL && all_pointers_to_this_object != NULL) {
	    assert(this->pointed_object != NULL);
	    all_pointers_to_this_object->insert(this);
	}

	assert((all_pointers_to_this_object == NULL) == (pointed_object == NULL));
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
	assert((this->all_pointers_to_this_object == NULL) == (this->pointed_object == NULL));
	// remove link to the object we pointed to until now
	point_nothing();

	// copy the data
	pointed_object = src.pointed_object;
	all_pointers_to_this_object = src.all_pointers_to_this_object;
	malloc_allocated = src.malloc_allocated;

	// add us to the set of pointers to this object
	if (pointed_object != NULL && all_pointers_to_this_object != NULL) {
	    assert(this->pointed_object != NULL);
	    all_pointers_to_this_object->insert(this);
	}

	assert((all_pointers_to_this_object == NULL) == (pointed_object == NULL));
    }

    template<class pointed_type> bool pointer<pointed_type>::points_to_NULL() const {
	return pointed_object == NULL;
    }

    template<class pointed_type> pointed_type& pointer<pointed_type>::operator*() {
	return *operator->();
    }

    template<class pointed_type> pointed_type* pointer<pointed_type>::operator->() const {
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

	assert(pointed_object != NULL);

	// we are pointing to something
	
	// remove us from the list of managed pointers to the object
	all_pointers_to_this_object->erase(all_pointers_to_this_object->find(this));

	// are we the last pointer pointing to this object? then we have to delete (free) the object
	if (all_pointers_to_this_object->empty()) {
	    if (malloc_allocated) {
		assert (pointed_object != NULL);
		std::free(pointed_object);
	    } else {
		assert (pointed_object != NULL);
		delete pointed_object;
	    }

	    delete all_pointers_to_this_object;
	}

	// we are now pointing to nothing
	all_pointers_to_this_object = NULL;
	pointed_object = NULL;
    }
}
