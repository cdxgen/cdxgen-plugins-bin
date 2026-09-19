package com.acme.dto

/** The request body's shape: a DTO whose FIELDS carry what was deserialized. */
data class OrderRequest(val customerName: String, val note: String)

/** An intermediate the mapper builds — object identity across a layer. */
class OrderCommand(val name: String, val trace: String)

/** The entity the repository stores. */
data class OrderRow(val name: String)
