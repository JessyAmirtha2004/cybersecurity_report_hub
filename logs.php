<div class="container py-5">
    <div class="d-flex w-100">
        <h3 class="col-auto flex-grow-1"><b>Audit Trail</b></h3>
        <button class="btn btn-sm btn-primary rounded-0" type="button" onclick="location.reload()"><i class="fa fa-retweet"></i> Refresh List</button>
    </div>
    <hr>
    <div class="card">
        <div class="card-body">
            <table class="table table-bordered table-striped table-hover">
                <thead>
                    <tr>
                        <th class="py-1 px-2">#</th>
                        <th class="py-1 px-2">DateTime</th>
                        <th class="py-1 px-2">Username</th>
                        <th class="py-1 px-2">Action Made</th>
                    </tr>
                </thead>
                <tbody>
                    <?php 
                    $qry = $conn->query("SELECT l.*,u.username FROM `logs` l inner join users u on l.user_id = u.id order by  unix_timestamp(l.`date_created`) asc");
                    $i = 1;
                    while($row=$qry->fetch_assoc()):
                    ?>
                    <tr>
                        <td class="py-1 px-2"><?php echo $i++ ?></td>
                        <td class="py-1 px-2"><?php echo date("M d, Y H:i",strtotime($row['date_created'])) ?></td>
                        <td class="py-1 px-2"><?php echo $row['username'] ?></td>
                        <td class="py-1 px-2"><?php echo $row['action_made'] ?></td>
                    </tr>
                    <?php endwhile; ?>
                    <?php if($qry->num_rows <=0): ?>
                        <tr>
                            <th class="tex-center"  colspan="4">No data to display.</th>
                        </tr>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
    </div>
</div>
