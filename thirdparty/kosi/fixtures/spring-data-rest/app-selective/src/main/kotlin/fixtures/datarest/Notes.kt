// Spring Data's "selectively exposing CRUD methods": extend the bare
// Repository<T, ID> marker and DECLARE what should exist. Every CRUD name
// is declared here, so each is CRUD plumbing (never a search resource), and
// the declared ones back their routes; a query method is still a search
// route. A bare-marker repository used to be invisible.
//
// kosi:want endpoint framework=spring-mvc path=/notes method=GET mode=resolved
// kosi:want endpoint framework=spring-mvc path=/notes method=POST mode=resolved
// kosi:want endpoint framework=spring-mvc path=/notes/{id} method=DELETE mode=resolved
// kosi:want endpoint framework=spring-mvc path=/notes/search/findByTitle method=GET mode=resolved
// kosi:want-not endpoint framework=spring-mvc path=/notes/search/save
// kosi:want-not endpoint framework=spring-mvc path=/notes/search/saveAll
// kosi:want-not endpoint framework=spring-mvc path=/notes/search/saveAndFlush
// kosi:want-not endpoint framework=spring-mvc path=/notes/search/saveAllAndFlush
// kosi:want-not endpoint framework=spring-mvc path=/notes/search/findById
// kosi:want-not endpoint framework=spring-mvc path=/notes/search/existsById
// kosi:want-not endpoint framework=spring-mvc path=/notes/search/findAll
// kosi:want-not endpoint framework=spring-mvc path=/notes/search/findAllById
// kosi:want-not endpoint framework=spring-mvc path=/notes/search/count
// kosi:want-not endpoint framework=spring-mvc path=/notes/search/deleteById
// kosi:want-not endpoint framework=spring-mvc path=/notes/search/delete
// kosi:want-not endpoint framework=spring-mvc path=/notes/search/deleteAllById
// kosi:want-not endpoint framework=spring-mvc path=/notes/search/deleteAll
// kosi:want-not endpoint framework=spring-mvc path=/notes/search/deleteAllInBatch
// kosi:want-not endpoint framework=spring-mvc path=/notes/search/deleteInBatch
// kosi:want-not endpoint framework=spring-mvc path=/notes/search/deleteAllByIdInBatch
// kosi:want-not endpoint framework=spring-mvc path=/notes/search/flush
// kosi:want-not endpoint framework=spring-mvc path=/notes/search/getById
// kosi:want-not endpoint framework=spring-mvc path=/notes/search/getOne
// kosi:want-not endpoint framework=spring-mvc path=/notes/search/getReferenceById
// kosi:want-not endpoint framework=spring-mvc path=/drafts
package fixtures.datarest

import org.springframework.data.repository.Repository

class Note(val id: Long = 0)

interface NoteRepository : Repository<Note, Long> {
    fun save(): Any?
    fun saveAll(): Any?
    fun saveAndFlush(): Any?
    fun saveAllAndFlush(): Any?
    fun findById(): Any?
    fun existsById(): Any?
    fun findAll(): Any?
    fun findAllById(): Any?
    fun count(): Any?
    fun deleteById(): Any?
    fun delete(): Any?
    fun deleteAllById(): Any?
    fun deleteAll(): Any?
    fun deleteAllInBatch(): Any?
    fun deleteInBatch(): Any?
    fun deleteAllByIdInBatch(): Any?
    fun flush(): Any?
    fun getById(): Any?
    fun getOne(): Any?
    fun getReferenceById(): Any?
    fun findByTitle(title: String): List<Note>
}

class Draft(val id: Long = 0)

// The bare marker with NOTHING declared exports no route.
interface DraftRepository : Repository<Draft, Long>
