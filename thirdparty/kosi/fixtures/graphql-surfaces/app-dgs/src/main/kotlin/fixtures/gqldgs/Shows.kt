// Netflix DGS: @DgsComponent fetchers, served at dgs.graphql.path. This
// module sets no Spring GraphQL keys, and a sibling's never leak in.
//
// kosi:want-not diagnostic code=parse-error
// kosi:want endpoint framework=graphql path=/dgs method=POST fn=~ShowsFetcher.shows mode=resolved
// kosi:want endpoint framework=graphql path=/dgs method=POST fn=~ShowsFetcher.addShow mode=resolved
// kosi:want endpoint framework=graphql path=/dgs method=POST fn=~ShowsFetcher.reviews mode=resolved
// kosi:want endpoint framework=graphql path=/dgs method=POST fn=~ShowsFetcher.showAdded mode=resolved
//
// Negative half: no WebSocket, GraphiQL or schema route here; a class
// without @DgsComponent is not a fetcher.
// kosi:want-not endpoint framework=graphql path=/graphql-ws fn=~ShowsFetcher
// kosi:want-not endpoint framework=graphql path=/graphql fn=~ShowsFetcher
// kosi:want-not endpoint framework=graphql fn=~NotAFetcher
package fixtures.gqldgs

import com.netflix.graphql.dgs.DgsComponent
import com.netflix.graphql.dgs.DgsData
import com.netflix.graphql.dgs.DgsMutation
import com.netflix.graphql.dgs.DgsQuery
import com.netflix.graphql.dgs.DgsSubscription
import com.netflix.graphql.dgs.InputArgument

class Show(val title: String)

@DgsComponent
class ShowsFetcher {
    @DgsQuery
    fun shows(@InputArgument titleFilter: String?): List<Show> = emptyList()

    @DgsMutation
    fun addShow(@InputArgument title: String): Show = Show(title)

    @DgsSubscription
    fun showAdded(): Show = Show("new")

    @DgsData(parentType = "Show", field = "reviews")
    fun reviews(): List<String> = emptyList()
}

class NotAFetcher {
    @DgsQuery
    fun hidden(): String = "h"
}
