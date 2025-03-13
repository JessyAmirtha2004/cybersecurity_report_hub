<div class="container py-5">
    <h3><b>Members List</b></h3>
    <div class="card">
        <div class="card-body">
            <div class="col-12 my-2 d-flex justify-content-end">
                <button class="btn btn-sm btn-primary rounded-0" id="add_new"><i class="fa fa-plus"></i> Add New</button>
            </div>
            <table class="table table-bordered table-striped table-hover">
                <thead>
                    <tr>
                        <th class="py-1 px-2">#</th>
                        <th class="py-1 px-2">First Name</th>
                        <th class="py-1 px-2">Last Name</th>
                        <th class="py-1 px-2">Contact #</th>
                        <th class="py-1 px-2">Address</th>
                        <th class="py-1 px-2">Action</th>
                    </tr>
                </thead>
                <tbody>
                    <?php 
                    $qry = $conn->query("SELECT * FROM members order by firstname asc, lastname asc");
                    $i = 1;
                    while($row=$qry->fetch_assoc()):
                    ?>
                    <tr>
                        <td class="py-1 px-2"><?php echo $i++ ?></td>
                        <td class="py-1 px-2"><?php echo $row['firstname'] ?></td>
                        <td class="py-1 px-2"><?php echo $row['firstname'] ?></td>
                        <td class="py-1 px-2"><?php echo $row['contact'] ?></td>
                        <td class="py-1 px-2"><?php echo $row['address'] ?></td>
                        <td class="py-1 px-2 text-center">
                            <div class="btn-group" role="group">
                                <button id="btnGroupDrop1" type="button" class="btn btn-primary dropdown-toggle btn-sm rounded-0 py-0" data-bs-toggle='dropdown' aria-expanded="false" >
                                Action
                                </button>
                                <ul class="dropdown-menu" aria-labelledby="btnGroupDrop1">
                                <li><a class="dropdown-item view_data" href="javascript:void(0)" data-id="<?php echo $row['id'] ?>">View</a></li>
                                <li><a class="dropdown-item edit_data" href="javascript:void(0)" data-id="<?php echo $row['id'] ?>">Edit</a></li>
                                <li><a class="dropdown-item delete_data" href="javascript:void(0)" data-id="<?php echo $row['id'] ?>" data-name="<?php echo "[id={$row['id']}] ".$row['firstname'].' '.$row['lastname'] ?>">Delete</a></li>
                                </ul>
                            </div>
                        </td>
                    </tr>
                    <?php endwhile; ?>
                    <?php if($qry->num_rows <=0): ?>
                        <tr>
                            <th class="tex-center" colspan="6">No data to display.</th>
                        </tr>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
    </div>
</div>

<script>
    $(function(){
        $('#add_new').click(function(){
            uni_modal('New Member',"manage_member.php");
        })
        $('.edit_data').click(function(){
            uni_modal('Edit Member Details',"manage_member.php?id="+$(this).attr('data-id'));
        })
        $('.delete_data').click(function(){
            _conf("Ar you sure to delete <b>"+$(this).attr('data-name')+"</b> from member list?","delete_data",[$(this).attr('data-id')])
        })
        $('.view_data').click(function(){
            uni_modal('View Member Details',"view_member.php?id="+$(this).attr('data-id'));
        })
    })
    function delete_data($id){
        $('#confirm_modal button').attr('disabled',true)
        $.ajax({
            url:'./Actions.php?a=delete_member',
            method:'POST',
            data:{id:$id},
            dataType:'JSON',
            error:err=>{
                console.log(err)
                alert("An error occurred.")
                $('#confirm_modal button').attr('disabled',false)
            },
            success:function(resp){
                if(resp.status == 'success'){
                    location.reload()
                }else{
                    alert("An error occurred.")
                    $('#confirm_modal button').attr('disabled',false)
                }
            }
        })
    }
</script>