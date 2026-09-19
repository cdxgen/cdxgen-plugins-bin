package fixtures.deep.layered

import java.util.UUID

class OrderMapper {
    fun map(raw: String): String {
        return "order:" + raw
    }

    fun mapSanitized(raw: String): String {
        // The sanitizer the negative half hangs on: the same shape, the same
        // layers, the same sinking implementation - and no finding.
        return "order:" + UUID.fromString(raw.trim()).toString()
    }
}
